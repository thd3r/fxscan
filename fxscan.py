#!/usr/bin/env python3

import os
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

# External library
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException

def main(args):
    if not args.input:
        target = sys.stdin.read().strip().split()
    else:
        target = args.input.split() if not os.path.isfile(args.input) else open(args.input, "r").read().strip().split()

    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")

    driver = webdriver.Chrome(options=options)

    for url in target:        
        try:
            driver.get(url)
            if args.timeout:
                WebDriverWait(driver, args.timeout).until(EC.alert_is_present(), message="timeout until the warning appears.")
            else: pass
            driver.switch_to.alert.accept()
            print("\033[32mPossible xss appears on the page:", url, "\033[0m")
            continue
        except TimeoutException:
            print("\033[31mTimeout:", url, "\033[0m")
            continue
        except NoAlertPresentException:
            if args.only_poc:
                pass
            else:
                print("\033[90mNo xss appears on the page:", url, "\033[0m")
                continue
        except UnexpectedAlertPresentException:
            print("\033[33mAn unexpected xss appeared on the page:", url, "\033[0m")
            continue
        except Exception:
            continue
        except KeyboardInterrupt:
            time.sleep(1)
            driver.quit()
            print("")
            break

    driver.quit()

if __name__ == "__main__":
   parser = argparse.ArgumentParser(prog="fxscan", usage="%(prog)s --input [target]")
   parser.add_argument(
       "-v",
       "--version",
       action="version",
       version="%(prog)s v0.1"
   )
   parser.add_argument(
       "-i",
       "--input",
       action="store",
       help="the target input includes its payload"
   )
   parser.add_argument(
       "-c",
       "--threads",
       type=int,
       default=50,
       help="number of concurrent threads (default: 50)"
   )
   parser.add_argument(
       "-t",
       "--timeout",
       type=float,
       help="timeout until the warning appears"
   )
   parser.add_argument(
       "-op",
       "--only-poc",
       action="store_true",
       help="show only potentially vulnerable urls"
   )

   print(open("static/fxscan_banner.txt", "r").read())
   args = parser.parse_args()
   
   with ThreadPoolExecutor(max_workers=args.threads) as executor:
       try:
           executor.submit(main(args))
       finally:
           executor.shutdown()