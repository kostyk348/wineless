<div align="center">

```
 ██╗    ██╗██╗███╗   ██╗███████╗██╗     ███████╗███████╗
 ██║    ██║██║████╗  ██║██╔════╝██║     ██╔════╝██╔════╝
 ██║ █╗ ██║██║██╔██╗ ██║█████╗  ██║     █████╗  ███████╗
 ██║███╗██║██║██║╚██╗██║██╔══╝  ██║     ██╔══╝  ╚════██║
 ╚███╔███╔╝██║██║ ╚████║███████╗███████╗███████╗███████║
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚══════╝
```

# wineless

**Запуск Windows x64 PE-бинарников на Linux. Без Wine. Без VM. Один C-файл.**

[![CI](https://github.com/example/wineless/actions/workflows/ci.yml/badge.svg)](https://github.com/example/wineless/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86__64-black)]()
[![Python](https://img.shields.io/badge/python-3.9%2B-green)]()

*English README: [README.md](README.md)*

</div>

---

## Коротко

```console
$ ./examples/run_jq.sh
[wineless] base=0x140000000 entry_rva=0x13f0 cmdline='"jq.exe" --version'
[wineless] executing PE entry point...
jq-1.7.1
[wineless] ExitProcess(0) captured

$ echo $?
0
```

Это **официальный `jq.exe`, собранный Microsoft-компилятором** (985 КБ, MSVC,
полноценный CRT), выполняющийся на Linux нативно. Wine не участвует — нет
ни одного процесса Wine, ни контейнера, ни слоя эмуляции. Есть только
C-лоадер на ~800 строк, который:

1. сам разбирает PE64-заголовки,
2. отображает секции в анонимную память,
3. применяет базовые релокации `DIR64`,
4. резолвит импорты по рукописной таблице хуков в конвенции `ms_abi`,
5. устанавливает фальшивые **TEB/PEB** (с рабочим TLS-массивом!) через
   `arch_prctl`,
6. прыгает на точку входа и перехватывает `ExitProcess()` через
   `setjmp/longjmp`.

А поскольку мы принципиально не требуем ни Windows, ни MinGW, wineless
несёт с собой **`pegen`** — генератор минимальных PE64-бинарников на чистом
Python. Весь конвейер тестируется end-to-end на любом Linux, офлайн.

```console
$ wineless synth demo.exe "привет из рукотворного PE"
[+] synthesized demo.exe (1536 bytes)
$ wineless run demo.exe
привет из рукотворного PE
$ echo $?
42
```

## Зачем

Wine — 30-летний монстр на 4 миллиона строк. Иногда хочется обратного:
минимально возможный мост между Windows-бинарником и ядром Linux,
достаточно маленький, чтобы прочитать его за один вечер. wineless — этот
мост, собранный как исследовательский артefакт:

- **Понять формат PE**, загрузив его вручную: заголовки, секции,
  релокации, IAT, TLS.
- **Понять границу ABI**: каждый хук объявлен `ms_abi`, поэтому один и тот
  же C-файл обслуживает гостя с конвенцией Microsoft на хосте с System-V.
  Самое сложное — CRT-мост (memcpy, qsort, printf), см. «Как это работает».
- **Понять, что такое ОС на самом деле**: ноутбук, с которого начался
  проект (`notebooks/01_meta_kernel_pe_loader.ipynb`), сводит файловые и
  потоковые API к трём Lisp-примитивам — `:res/alloc`, `:res/mutate`,
  `:sig/emit` — и показывает Win32 и POSIX как два макро-пакета над одним
  ядром.

## Архитектура

```
                    wineless run jq.exe --version
                              │
                              ▼
  ┌─────────────────────────── Python-оркестрация ────────────────────────┐
  │  cli.py ─► loader.py ─► cbuild.py (cc -O2, кэш по хэшу исходника)     │
  │     │            │                                                    │
  │     │            └──► pe.py     PE32+ парсер на чистом Python         │
  │     └──► kernel.py  Lisp-метаядро (:res/alloc/:res/mutate/:sig/emit)  │
  │              └──► pegen.py  генератор минимальных PE64 (тесты/демо)   │
  └───────────────────────────────┬───────────────────────────────────────┘
                                  │ subprocess
                                  ▼
  ┌────────────────────────── wineless_loader.c ──────────────────────────┐
  │  1. чтение PE    MZ → PE\0\0 → COFF → Optional(PE32+) → секции        │
  │  2. mmap образа  желаемый ImageBase, при конфликте — куда получится   │
  │  3. копия + релокации  заголовки, секции, DIR64-релокации базы        │
  │  4. резолв IAT   250+ хуков ms_abi: kernel32 + ucrtbase + libm        │
  │  5. фейк TEB/PEB arch_prctl(ARCH_SET_GS) + ThreadLocalStoragePointer  │
  │  6. entry()      ловушка setjmp/longjmp для ExitProcess()             │
  └───────────────────────────────────────────────────────────────────────┘
```

## Как это работает

**Граница ABI.** Windows-бинарник ждёт конвенцию Microsoft x64: целые
аргументы в `rcx, rdx, r8, r9`, дробные в `xmm0..3`, 32 байта shadow space.
Наши хуки собраны с `__attribute__((ms_abi))` — GCC делает перевод сам. Но
ловушек повсюду:

- **`wchar_t` — 2 байта на Windows и 4 на Linux.** Все wide-хуки
  (`GetCommandLineW`, `MultiByteToWideChar`, `wcslen`...) работают с UTF-16
  явно, через тип `uint16_t`. Наивная версия с `wchar_t*` падает зрелищно.
- **`__p___argv` возвращает `char***`**, а не `char**` — UCRT возвращает
  *адрес переменной*, и стартовый код MSVC разыменовывает его дважды.
- **`qsort` принимает указатель на компаратор**, который будет *вызван
  обратно*: libc-`qsort` вызвал бы Microsoft-компаратор с аргументами
  System-V. wineless несёт собственную сортировку вставками, вызывающую
  компаратор через указатель функции с `ms_abi`.
- **MSVC пропускает `printf` через `__stdio_common_vfprintf`** с MS-ABI
  `va_list`. У GCC нет `ms_vsnprintf`, поэтому хук переобъявлен как
  ms-вариативная функция, а форматная строка разбирается вручную с
  извлечением аргументов через `__builtin_va_arg`.

**Мета-ядро.** `wineless kernel` запускает философское демо: Win32
`CreateFileW` и POSIX `open()` раскрываются в одни и те же три примитива:

```lisp
(:let h
  (:res/alloc "stream" {:name "data.bin" :lock "FILE_SHARE_READ"})
  (:sig/emit :h "FILE_OPENED" {:access "GENERIC_WRITE"})
  :h)
```

Системный вызов — это выделение ресурса плюс сигнал. Всё остальное —
макросы.

## Бенчмарки

| Нагрузка                                    | Время        | Примечание                        |
|---------------------------------------------|--------------|-----------------------------------|
| `wineless run demo.exe` (синтетический PE)  | ~1 мс        | вместе со стартом лоадера         |
| `wineless run jq.exe --version` (официальный)| ~10 мс      | 210 импортов разрешено, exit 0    |
| сборка лоадера (кэшируется)                 | ~0.4 с один раз | пересчитывается по хэшу исходника |

Разумеется, цифры зависят от железа — это эмулятор, а не гонка.

## Установка

```bash
git clone https://github.com/example/wineless
cd wineless
pip install -e .
wineless --help
```

Требования: Linux x86_64, любой C-компилятор (`cc`/`gcc`/`clang`),
Python 3.9+. Больше никаких зависимостей.

## Справка по CLI

```
wineless info   <file.exe>            дамп заголовков, секций, импортов
wineless run    <file.exe> [args...]  запуск Windows PE64
wineless synth  <out.exe> [message]   синтез демо-PE на чистом Python
wineless kernel                       демо Lisp-метаядра
```

Переменная окружения `WINELESS_TRACE=1` включает трассировку вызовов
(зонды `wcslen`, промахи `GetProcAddress`) — незаменимо при портировании
нового бинарника.

## Что работает / что нет

| ✅ работает                                              | ❌ пока нет                                |
|----------------------------------------------------------|---------------------------------------------|
| синтетический PE64 от `pegen` (на любом Linux)           | PE32 (32-битные образы)                     |
| консольные бинарники MSVC: `jq.exe --version`            | полная семантика locale/stdio ucrtbase      |
| CRT-мост: память, строки, `printf`, `qsort`, libm        | исключения / SEH (проглатываются)           |
| базовые релокации, статический TLS-массив, хендлы консоли| потоки (`_beginthreadex` — заглушка)        |
| раскладка TEB/PEB с честными смещениями x64              | GUI-подсистема, GDI                         |

Идеи роадмапа: настоящий `argv` из окружения ОС для `main()`, поддержка
PE32, режим трассировки системных вызовов, загрузка настоящих DLL.

## Структура репозитория

```
wineless/
├── c/wineless_loader.c        лоадер (один файл, ~900 строк)
├── src/wineless/              Python-пакет
│   ├── pe.py                  парсер PE32+
│   ├── pegen.py               генератор минимальных PE64
│   ├── kernel.py              Lisp-метаядро
│   ├── cbuild.py              компиляция в рантайме + кэш
│   ├── loader.py              оркестрация
│   └── cli.py                 argparse-CLI
├── tests/                     23 pytest-кейса, включая end-to-end запуск PE
├── examples/                  build_hello_pe.py, run_jq.sh
├── notebooks/                 исходный исследовательский ноутбук (Colab)
└── .github/workflows/ci.yml   юнит-тесты + интеграция с jq.exe на ubuntu-latest
```

## Смежные проекты

- [Wine](https://www.winehq.org) — полная реализация; wineless — анти-Wine:
  минимальная жизнеспособная эмуляция ради исследования, а не совместимости.
- [Fex-Emu](https://fex-emu.com), [Box64](https://github.com/ptitSeb/box64) —
  эмуляторы уровня инструкций; wineless не эмулирует инструкции (x64
  исполняется нативно), он лишь поставляет *окружение*.
- *Practical Binary Analysis* (Dennis Yurichev) — домашнее задание по PE,
  которое этот проект случайно превратил в хобби.

## Лицензия

Apache-2.0 — см. [LICENSE](LICENSE).
Исследовательский артefакт: ждите шероховатости, читайте исходники,
ломайте.
