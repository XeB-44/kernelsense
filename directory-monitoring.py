import sys
import time
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

path1 = "/etc/init.d/"
path2 = "/etc/systemd/"
path3 = "/var/log/journal/"

event_handler = LoggingEventHandler()


observer = Observer()
observer.schedule(event_handler, path1, recursive=True)
observer.schedule(event_handler, path2, recursive=True)
observer.schedule(event_handler, path3, recursive=True)
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()

