# bot/bot.py
import os
import json
import logging
import asyncio
import time
import tempfile
import requests
import shutil
import io
import base64

from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import Message, ContentType, CallbackQuery, InputFile
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.types import BotCommand, BotCommandScopeDefault

from bot.checker import analyze_url

load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")
if not TOKEN:
    raise RuntimeError("TELEGRAM_TOKEN is not set in .env")

API_SAVE_URL = os.getenv("API_SAVE_URL", "http://127.0.0.1:8000/report")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

bot = Bot(token=TOKEN)
dp = Dispatcher()

AWAITING_LINK = {}
AWAITING_FALSE_POSITIVE = set()
WAIT_TIMEOUT = 15 * 60

DEFAULT_COMMANDS = [
    BotCommand(command="start", description="Ботты бастау / басты мәзір"),
    BotCommand(command="help", description="Қалай қолдану туралы қысқаша нұсқаулық"),
    BotCommand(command="report_link", description="Күдікті сілтемені немесе файлды жедел хабарлау"),
    BotCommand(command="false_positive", description="Қате анықталған нәтиже туралы хабарландыру"),
    BotCommand(command="report", description="(админ) барлық репорттарды көру"),
    BotCommand(command="history", description="Боттың шығу тарихы")
]

def set_awaiting(user_id: int):
    AWAITING_LINK[user_id] = time.time()

def clear_awaiting(user_id: int):
    if user_id in AWAITING_LINK:
        del AWAITING_LINK[user_id]

def is_awaiting(user_id: int) -> bool:
    ts = AWAITING_LINK.get(user_id)
    if not ts:
        return False
    if time.time() - ts > WAIT_TIMEOUT:
        clear_awaiting(user_id)
        return False
    return True

def _truncate_text(s: str, limit: int = 400) -> str:
    if s is None:
        return ""
    s = str(s).strip()
    if len(s) <= limit:
        return s

    part = s[:limit].rsplit(" ", 1)[0]
    if not part:
        part = s[:limit]
    return part + "…"

def format_analysis_result(res: dict, ocr_max: int = 400) -> str:
    try:
        conf = int((res.get("confidence", 0) or 0) * 100)
    except Exception:
        conf = 0

    if conf >= 70:
        verdict = "Қауіпті 🛑"
    elif conf >= 30:
        verdict = "Күмәнді ⚠️"
    else:
        verdict = "Қауіпсіз ✅"

    lines = [f"🔍 Қорытынды: *{verdict}* ({conf}%)"]

    reasons = res.get("reasons") or []
    if not reasons:
        try:
            anns = res.get("analyses") or []
            if isinstance(anns, list) and len(anns) > 0:
                reasons = anns[0].get("reasons") or []
        except Exception:
            reasons = []

    if reasons:
        lines.append("\nНегізгі себептер:")
        for r in reasons[:8]:
            lines.append(f"• {r}")

    # candidates (URLs/files)
    candidates = res.get("candidates") or []
    if not candidates:
        try:
            anns = res.get("analyses") or []
            if isinstance(anns, list) and len(anns) > 0:
                candidates = [a.get("url") or a.get("file_name") or "" for a in anns]
        except Exception:
            candidates = []

    if candidates:
        lines.append("\nТабылған кандидаттар:")
        for c in candidates[:6]:
            if c:
                lines.append(f"• {c}")

    final = None
    try:
        final = (res.get("analysis_details") or {}).get("final_url") or res.get("final_url") or res.get("url")
        if not final and res.get("analyses"):
            a0 = res["analyses"][0]
            final = (a0.get("analysis_details") or {}).get("final_url") or a0.get("url")
    except Exception:
        final = final or None

    if final:
        lines.append(f"\nБолжамды финал URL: {final}")

    ocr_text = ""
    try:
        ocr_text = res.get("ocr_text") or ""
        if not ocr_text:
            anns = res.get("analyses") or []
            for a in anns:
                ad = a.get("analysis_details") or {}
                if isinstance(ad, dict):
                    if ad.get("ocr_text"):
                        ocr_text = ad.get("ocr_text")
                        break
                    fa = ad.get("file_analysis") or {}
                    if isinstance(fa, dict):
                        for key in ("ocr_text", "embedded_text", "text", "strings"):
                            if fa.get(key):
                                ocr_text = fa.get(key)
                                break
                        if ocr_text:
                            break
    except Exception:
        ocr_text = ""

    if ocr_text:
        nice = _truncate_text(ocr_text, limit=ocr_max)
        lines.append(f"\nФайл ішінде: \"{nice}\"")

    lines.append("\nЕскерту: Егер нәтиже дұрыс емес болса, /false_positive командасын қолданыңыз.")
    return "\n".join(lines)

@dp.message(Command("start"))
async def cmd_start(message: Message):
    builder = InlineKeyboardBuilder()
    builder.button(text="🔗 Сілтемені тексеру", callback_data="start_report")
    kb = builder.as_markup()
    await message.answer(
        "Сәлем! Бұл қазақша бот күдікті сілтемелер мен файлдарды тексеруге арналған.\n\n"
        "Төмендегі батырманы басып, содан кейін тексергіңіз келетін сілтемені немесе файлды жіберіңіз.\n\n"
        "Ескерту! Бот сізге толық ақпарат бере алмауы мүмкін. Тек сілтемені анықтап, хабар береді. Соңғы шешімді өзіңіз қабылдайсыз!",
        reply_markup=kb
    )

@dp.message(Command("help"))
async def help_cmd(message: Message):
    await message.answer(
        "Сәлем! 👋\n\n"
        "Бұл бот күдікті сілтемелер мен файлдарды тексеруге арналған.\n\n"
        "Қалай қолдану керек:\n"
        "1️⃣ /report_link командасын басыңыз\n"
        "2️⃣ Сілтемені немесе файлды жіберіңіз\n"
        "3️⃣ Бот сізге қауіп деңгейін көрсетеді\n\n"
        "Егер нәтиже қате болса — /false_positive командасын қолданыңыз."
    )

@dp.message(Command("report_link"))
async def report_link_cmd(message: Message):
    set_awaiting(message.from_user.id)
    await message.answer("🔗 Сілтемені немесе файлды жіберіңіз.")

@dp.message(Command("false_positive"))
async def false_positive_cmd(message: Message):
    user_id = message.from_user.id
    AWAITING_FALSE_POSITIVE.add(user_id)
    await message.answer("Қате анықталған сілтемені қайта жіберіңіз.")

@dp.message(Command("history"))
async def history_cmd(message: Message):
    await message.answer(
        "Бұл қазақ тілінде жасалған анти-скам бот.\n\n"
        "Ботты әзірлеген — Жомартұлы Бекасыл және Иманалы Рашид есімді, "
        "\"ҚазҰТЗУ - Сәтбаев университетінің\" Computer Science мамандығын аяқтаған студенттері.\n\n"
        "Ботты әзірлеу себебі:\n"
        "2019 жылы \"COVID-19\" вирусы кезінен бастап көптеген алаяқтар "
        "өздерінің айласын асыра бастаған еді.\n\n"
        "Қазіргі уақытта алаяқтар өте кәсіби дәрежеге көтеріліп, "
        "алданған халықтың саны 6-7 жыл бұрын қарағанда едәуір өсті.\n\n"
        "Ал студенттер өздерінің аздаған болса да халыққа көмегі тию үшін "
        "және халықтың көзін ашу үшін осы ботты әзірледі."
    )

@dp.callback_query(F.data == "start_report")
async def cb_start_report(query: CallbackQuery):
    user_id = query.from_user.id
    set_awaiting(user_id)
    await query.message.answer("✔️ Дайын. Қазір сілтемені немесе файлды жіберіңіз. (15 минут ішінде жібермесеңіз, сұрау аяқталады.)")
    await query.answer()

@dp.message(F.text)
async def handle_text(message: Message):
    user_id = message.from_user.id
    text = (message.text or "").strip()

    try:
        if user_id in AWAITING_FALSE_POSITIVE:
            try:
                AWAITING_FALSE_POSITIVE.discard(user_id)
            except Exception:
                pass

            payload = {
                "url": text,
                "reported_by": str(user_id),
                "source": "false_positive",
                "file_type": None,
                "file_name": None,
                "ocr_text": None,
                "analysis_details": {"note": "Marked as false positive by user", "reported_text": text},
                "confidence": 0.0
            }

            try:
                asyncio.create_task(post_report_async(payload))
            except Exception:
                try:
                    await post_report_async(payload)
                except Exception:
                    logger.exception("Failed to post false_positive payload for user %s", user_id)

            await message.answer(
                "Рахмет! ✅\n\n"
                "Біз бұл қателікті админге сақтадық.\n"
                "Бұл қателікті түзетуге жұмыс жасаймыз!"
            )
            return
    except Exception:
        logger.exception("Error handling false-positive mode for user %s", user_id)

    if is_awaiting(user_id):
        loading = await message.answer("Тексерілуде — күте тұрыңыз...")
        try:
            try:
                res = analyze_url(input_text=text, file_path=None)
            except Exception as e:
                await loading.edit_text(f"Талдау кезінде қате: {e}")
                clear_awaiting(user_id)
                return

            formatted = format_analysis_result(res)
            try:
                await loading.edit_text(formatted)
            except Exception:
                try:
                    await loading.edit_text(formatted.replace("*", ""))
                except Exception:
                    await message.answer(formatted.replace("*", ""))

            first_analysis = None
            try:
                if res.get("analyses") and isinstance(res.get("analyses"), list) and len(res.get("analyses")) > 0:
                    first_analysis = res["analyses"][0]
                else:
                    first_analysis = res
            except Exception:
                first_analysis = res

            render_info = {}
            llm_summary = None
            screenshot = None
            title = None
            excerpt = None

            try:
                ai_details = (first_analysis.get("analysis_details") if isinstance(first_analysis, dict) else None) or {}
                render_info = ai_details.get("render") or (res.get("analysis_details") or {}).get("render") or {}

                title = render_info.get("title") or render_info.get("doc_title") or render_info.get("short_title")
                excerpt = render_info.get("excerpt") or render_info.get("text") or render_info.get("text_excerpt")

                llm_summary = ai_details.get("llm_summary") or res.get("llm_summary") or render_info.get("llm_summary")
                screenshot = render_info.get("screenshot") or ai_details.get("screenshot") or res.get("screenshot")
            except Exception:
                pass

            follow_lines = []
            if title:
                follow_lines.append(f"Тақырып: {title}")
            if excerpt:
                ex = (excerpt.strip().replace("\n", " ")[:600]).rsplit(" ", 1)[0]
                follow_lines.append(f"Қысқаша: {ex}...")
            if llm_summary:
                follow_lines.append(f"Ескерту (LLM): {llm_summary}")

            if follow_lines:
                try:
                    await message.answer("\n".join(follow_lines))
                except Exception:
                    pass

            if screenshot:
                try:
                    if isinstance(screenshot, str) and screenshot.startswith("data:image/"):
                        header, b64 = screenshot.split(",", 1)
                        img_bytes = base64.b64decode(b64)
                        bio = io.BytesIO(img_bytes)
                        bio.name = "preview.png"
                        bio.seek(0)
                        await bot.send_photo(chat_id=message.chat.id, photo=InputFile(bio), caption="Сайттың алдын ала қарауы (preview)")
                    else:
                        try:
                            await bot.send_photo(chat_id=message.chat.id, photo=screenshot, caption="Сайттың алдын ала қарауы (preview)")
                        except Exception:
                            r = requests.get(screenshot, stream=True, timeout=10)
                            r.raise_for_status()
                            img_bytes = r.content
                            bio = io.BytesIO(img_bytes)
                            bio.name = "preview.png"
                            bio.seek(0)
                            await bot.send_photo(chat_id=message.chat.id, photo=InputFile(bio), caption="Сайттың алдын ала қарауы (preview)")
                except Exception:
                    logger.exception("Failed to send screenshot to user %s", user_id)

            try:
                first_url = None
                if first_analysis and isinstance(first_analysis, dict):
                    first_url = (first_analysis.get("analysis_details") or {}).get("final_url") or first_analysis.get("url")
                if not first_url:
                    cand = res.get("candidates")
                    if cand and len(cand) > 0:
                        first_url = cand[0]
            except Exception:
                first_url = None

            payload = {
                "url": first_url,
                "reported_by": str(user_id),
                "source": "private",
                "file_type": None,
                "file_name": None,
                "ocr_text": res.get("ocr_text"),
                "analysis_details": res,
                "confidence": float(res.get("confidence") or 0)
            }

            if render_info:
                payload["render_info"] = render_info
            if llm_summary:
                payload["llm_summary"] = llm_summary
            if screenshot:
                payload["screenshot"] = screenshot

            try:
                asyncio.create_task(post_report_async(payload))
            except Exception:
                try:
                    await post_report_async(payload)
                except Exception:
                    logger.exception("Failed to post analysis payload for user %s", user_id)

        except Exception as e:
            logger.exception("Unhandled exception in text analysis flow for user %s: %s", user_id, e)
            try:
                await loading.edit_text(f"Ішкі қате: {e}")
            except Exception:
                pass
        finally:
            clear_awaiting(user_id)
        return

    builder = InlineKeyboardBuilder()
    builder.button(text="🔗 Сілтемені тексеру", callback_data="start_report")
    kb = builder.as_markup()
    await message.reply("Бастау үшін төмендегі батырманы басыңыз немесе /start жазыңыз.", reply_markup=kb)


@dp.message(F.content_type.in_({ContentType.DOCUMENT, ContentType.PHOTO}))
async def handle_file_message(message: Message):
    user_id = message.from_user.id
    if not is_awaiting(user_id):
        builder = InlineKeyboardBuilder()
        builder.button(text="🔗 Сілтемені тексеру", callback_data="start_report")
        kb = builder.as_markup()
        await message.reply("Ең алдымен тексеру режимін бастау қажет. Төмендегі батырманы басыңыз.", reply_markup=kb)
        return

    loading = await message.answer("Файл қабылданып, талданып жатыр...")
    tmp_name = None
    try:
        file_ext = None
        filename = None
        file_id = None
        if message.document:
            doc = message.document
            file_id = doc.file_id
            filename = doc.file_name or "upload"
            file_ext = os.path.splitext(filename)[1] or ""
        elif message.photo:
            # take largest photo
            photo = message.photo[-1]
            file_id = photo.file_id
            filename = "photo.jpg"
            file_ext = ".jpg"
        else:
            await loading.edit_text("Файл түрі анықталмады.")
            clear_awaiting(user_id)
            return

        file_info = await bot.get_file(file_id)
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=file_ext)
        tmp_name = tmp.name
        tmp.close()

        try:
            await bot.download(file_info.file_path, tmp_name)
        except Exception:
            try:
                await bot.download_file(file_info.file_path, tmp_name)
            except Exception:
                file_url = f"https://api.telegram.org/file/bot{TOKEN}/{file_info.file_path}"
                r = requests.get(file_url, stream=True, timeout=15)
                r.raise_for_status()
                with open(tmp_name, "wb") as fh:
                    for chunk in r.iter_content(8192):
                        fh.write(chunk)

        res = analyze_url(input_text=None, file_path=tmp_name, original_filename=filename)

        formatted = format_analysis_result(res)
        try:
            await loading.edit_text(formatted)
        except Exception:
            await loading.edit_text(formatted.replace("*", ""))

        first_analysis = None
        try:
            if res.get("analyses") and isinstance(res.get("analyses"), list) and len(res.get("analyses")) > 0:
                first_analysis = res["analyses"][0]
            else:
                first_analysis = res
        except Exception:
            first_analysis = res

        render_info = {}
        llm_summary = None
        screenshot = None
        title = None
        excerpt = None

        try:
            ai_details = (first_analysis.get("analysis_details") if isinstance(first_analysis, dict) else None) or {}
            render_info = ai_details.get("render") or (res.get("analysis_details") or {}).get("render") or {}
            title = render_info.get("title") or render_info.get("doc_title") or render_info.get("short_title")
            excerpt = render_info.get("excerpt") or render_info.get("text") or render_info.get("text_excerpt")
            llm_summary = ai_details.get("llm_summary") or res.get("llm_summary") or render_info.get("llm_summary")
            screenshot = render_info.get("screenshot") or ai_details.get("screenshot") or res.get("screenshot")
        except Exception:
            pass

        follow_lines = []
        if title:
            follow_lines.append(f"Тақырып: {title}")
        if excerpt:
            ex = (excerpt.strip().replace("\n", " ")[:600]).rsplit(" ", 1)[0]
            follow_lines.append(f"Қысқаша: {ex}...")
        if llm_summary:
            follow_lines.append(f"Ескерту (LLM): {llm_summary}")

        if follow_lines:
            try:
                await message.answer("\n".join(follow_lines))
            except Exception:
                pass

        if screenshot:
            try:
                if isinstance(screenshot, str) and screenshot.startswith("data:image/"):
                    header, b64 = screenshot.split(",", 1)
                    img_bytes = base64.b64decode(b64)
                    bio = io.BytesIO(img_bytes)
                    bio.name = "preview.png"
                    bio.seek(0)
                    await bot.send_photo(chat_id=message.chat.id, photo=InputFile(bio), caption="Сайттың алдын ала қарауы (preview)")
                else:
                    try:
                        await bot.send_photo(chat_id=message.chat.id, photo=screenshot, caption="Сайттың алдын ала қарауы (preview)")
                    except Exception:
                        r = requests.get(screenshot, stream=True, timeout=10)
                        r.raise_for_status()
                        img_bytes = r.content
                        bio = io.BytesIO(img_bytes)
                        bio.name = "preview.png"
                        bio.seek(0)
                        await bot.send_photo(chat_id=message.chat.id, photo=InputFile(bio), caption="Сайттың алдын ала қарауы (preview)")
            except Exception:
                logger.exception("Failed to send screenshot for file report to user %s", user_id)

        payload = {
            "url": None,
            "reported_by": str(user_id),
            "source": "file",
            "file_type": file_ext.lstrip(".") if file_ext else None,
            "file_name": filename,
            "ocr_text": res.get("ocr_text"),
            "analysis_details": res,
            "confidence": float(res.get("confidence") or 0)
        }

        if render_info:
            payload["render_info"] = render_info
        if llm_summary:
            payload["llm_summary"] = llm_summary
        if screenshot:
            payload["screenshot"] = screenshot

        try:
            asyncio.create_task(post_report_async(payload))
        except Exception:
            try:
                await post_report_async(payload)
            except Exception:
                logger.exception("Failed to post file analysis payload for user %s", user_id)

    except Exception as e:
        logger.exception("Error while handling file message: %s", e)
        try:
            await loading.edit_text(f"Файлты өңдеуде қате: {e}")
        except Exception:
            pass
    finally:
        clear_awaiting(user_id)
        try:
            if tmp_name and os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except Exception:
            pass

async def post_report_async(payload: dict, retries: int = 3, backoff: float = 1.0):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    def do_post_once(data_text: str):
        try:
            headers = {"Content-Type": "application/json"}
            r = requests.post(API_SAVE_URL, data=data_text.encode("utf-8"), headers=headers, timeout=10)
            return (r.status_code, r.text)
        except Exception as e:
            return ("EXC", str(e))

    try:
        json_text = json.dumps(payload, default=str, ensure_ascii=False)
    except Exception as e:
        logger.exception("Failed to json.dumps(payload): %s", e)
        try:
            payload_safe = {k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v)) for k, v in payload.items()}
            json_text = json.dumps(payload_safe, default=str, ensure_ascii=False)
        except Exception as e2:
            logger.exception("Failed second attempt to prepare payload for post: %s", e2)
            return

    for attempt in range(1, retries + 1):
        try:
            if loop:
                status, text = await loop.run_in_executor(None, do_post_once, json_text)
            else:
                status, text = do_post_once(json_text)
            logger.info("post_report_async attempt %d result: %s %s", attempt, status, text)

            try:
                if isinstance(status, int) and 200 <= status < 300:
                    return
            except Exception:
                pass
        except Exception as e:
            logger.exception("post_report_async exception on attempt %d: %s", attempt, e)

        await asyncio.sleep(backoff * attempt)

    logger.error("post_report_async failed after %d attempts. payload summary: reported_by=%s, source=%s, url=%s",
                 retries, payload.get("reported_by"), payload.get("source"), (payload.get("url") or payload.get("file_name")))

@dp.message(Command("help"))
async def help_cmd_repeat(message: Message):
    await message.answer(
        "Пайдалану:\n"
        "1) /start — басты мәзір\n"
        "2) 'Сілтемені тексеру' батырмасын басыңыз\n"
        "3) Келесі жібергеніңіз — бот талдайды (мәтін немесе файл)\n\n"
        "Командалар:\n/help - көмек\n/false_positive - егер нәтиже қате болса хабарлау"
    )

async def main():
    logger.info("Bot is starting...")

    try:
        await bot.set_my_commands(commands=DEFAULT_COMMANDS, scope=BotCommandScopeDefault())
        logger.info("Bot commands registered: %s", [c.command for c in DEFAULT_COMMANDS])
    except Exception as e:
        logger.exception("Failed to set bot commands: %s", e)

    try:
        await dp.start_polling(bot)
    except asyncio.CancelledError:
        logger.info("Polling cancelled (asyncio.CancelledError)")
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received inside polling")
    except Exception as e:
        logger.exception("Unexpected exception in polling: %s", e)
    finally:
        try:
            if hasattr(dp, "shutdown") and callable(getattr(dp, "shutdown")):
                try:
                    res = dp.shutdown()
                    if asyncio.iscoroutine(res):
                        await res
                except Exception as e:
                    logger.exception("Error when calling dp.shutdown(): %s", e)
        except Exception as e:
            logger.exception("Error during dispatcher shutdown check: %s", e)

        try:
            if hasattr(bot, "session") and bot.session is not None:
                try:
                    maybe = bot.session.close()
                    if asyncio.iscoroutine(maybe):
                        await maybe
                except TypeError:
                    try:
                        bot.session.close()
                    except Exception as e:
                        logger.exception("Error closing bot.session (sync path): %s", e)
                except Exception as e:
                    logger.exception("Error closing bot.session: %s", e)
        except Exception as e:
            logger.exception("Error while attempting to close bot.session: %s", e)

        try:
            if hasattr(dp, "storage") and dp.storage is not None:
                try:
                    sres = dp.storage.close()
                    if asyncio.iscoroutine(sres):
                        await sres
                except Exception:
                    try:
                        wres = getattr(dp.storage, "wait_closed", None)
                        if wres:
                            wr = wres()
                            if asyncio.iscoroutine(wr):
                                await wr
                    except Exception as e:
                        logger.exception("Error closing dp.storage: %s", e)
        except Exception as e:
            logger.exception("Error during storage shutdown: %s", e)

        logger.info("Bot stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received — exiting")
    except asyncio.CancelledError:
        logger.info("Asyncio CancelledError received — exiting")
    except Exception as e:
        logger.exception("Unhandled error in bot process: %s", e)
