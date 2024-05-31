
import inspect

db0 = True

# ----------------------------------------------------------------------------------------------
# debug.py
# ----------------------------------------------------------------------------------------------

INDENT_STR_DEFAULT = "    "
FLAG_ACTIVE_DEFAULT = True
FLAG_FORCE_LOCATION = False

def print_location(active=True, offset=0, levels=1, end="\n"):
    if not active:
        return

    for level in range(levels):
        caller_frame_record = inspect.stack()[level+offset+1]
        frame = caller_frame_record[0]
        info = inspect.getframeinfo(frame)
        file = info.filename
        print('[{}:{} {}()]'.format(file, info.lineno, info.function), end=end)

def debug_print(*args, **kwargs):
    if not db0:
        return

    if "active" in kwargs:
        active = kwargs.pop("active")
        if not active:
            return

    if "location" in kwargs:
        location = kwargs.pop("location")
    else:
        location = True

    if "indent_str" in kwargs:
        indent_str = kwargs.pop("indent_str")
    else:
        indent_str = INDENT_STR_DEFAULT

    prefix = ""
    if "indent" in kwargs:
        indent = kwargs.pop("indent")
        prefix = indent_str * indent
    else:
        prefix = indent_str

    line_start = ""
    if "new_line" in kwargs:
        flag_new_line = kwargs.pop("new_line")
        if flag_new_line:
            line_start = "\n"

    offset = 0
    if "offset" in kwargs:
        offset = kwargs.pop("offset")

    end = " "
    if "end" in kwargs:
        end = kwargs.pop("end")

    print(line_start + prefix, end="")

    if location or FLAG_FORCE_LOCATION:
        print_location(offset=1 + offset, end=end)

    print(*args, **kwargs)
