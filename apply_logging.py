import sys

path = 'dart_agent/src/dart_agent/live.py'
with open(path, 'r') as f:
    lines = f.readlines()

# 1. Add logging import
for i, line in enumerate(lines):
    if 'import argparse' in line:
        lines.insert(i, 'import logging\n')
        break

# 2. Add _setup_logging helper before live_run
setup_code = """
def _setup_logging():
    level_str = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stderr
    )
    return logging.getLogger("dart_agent.live")

"""

for i, line in enumerate(lines):
    if 'async def live_run' in line:
        lines.insert(i, setup_code)
        break

# 3. Replace print statements in live_run with logger calls
# We'll do this carefully. 
new_content = "".join(lines)
new_content = new_content.replace('    print(f"[live] case={case}', '    logger = _setup_logging()\n    logger.info(f"[live] case={case}')
new_content = new_content.replace('        print(f"[live] MCP handshake OK', '        logger.info(f"[live] MCP handshake OK')
new_content = new_content.replace('        print(f"[live] tools: {', '        logger.debug(f"[live] tools: {')
new_content = new_content.replace('    print(f"[live] done — {', '    logger.info(f"[live] done — {')
new_content = new_content.replace('    print(f"[live] outputs in: {', '    logger.info(f"[live] outputs in: {')

with open(path, 'w') as f:
    f.write(new_content)
