# debug.py
import inspect

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
