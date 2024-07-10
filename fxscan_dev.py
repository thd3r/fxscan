#!/usr/bin/env python3

import os
import sys
import time
import argparse

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlunparse, parse_qs

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException

class Options:

    def __init__(self, banner):
        banner

    @property
    def option_parser(self):
        parser = argparse.ArgumentParser(prog="fxscan", usage="%(prog)s [mode] [flags]")
        parser._optionals.title = "flags"
        parser.add_argument(
            "-v",
            "--version",
            action="version",
            version="%(prog)s v0.1"
        )

        subparser = parser.add_subparsers(title="available modes", metavar="gui,cli", dest="mode", required=True, help="list of available modes (choose gui or cli)")

        guiparser = subparser.add_parser(name="gui", prog="fxscan", help="run programs with a graphical interface", usage="%(prog)s gui [flags]")
        guiparser._optionals.title = "flags"
        guiparser.add_argument(
            "-i",
            "--input",
            action="store",
            metavar="target",
            help="the target used for scanner (list: single,file)"
        )
        guiparser.add_argument(
            "-p",
            "--payload",
            required=True,
            metavar="payload",
            action="store",
            help="the payload used for scanner (list: single,file)"
        )
        guiparser.add_argument(
            "-t",
            "--threads",
            type=int,
            metavar="int",
            default=50,
            help="number of concurrent threads (default: 50)"
        )
        guiparser.add_argument(
            "-pg",
            "--page-timeout",
            type=float,
            metavar="float",
            default=5,
            help="set the page load timeout (default: 5)"
        )

        cliparser = subparser.add_parser(name="cli", prog="fxscan", help="run programs without a graphical interface", usage="%(prog)s cli [flags]")
        cliparser._optionals.title = "flags"
        cliparser.add_argument(
            "-i",
            "--input",
            action="store",
            metavar="target",
            help="the target used for scanner (list: single,file)"
        )
        cliparser.add_argument(
            "-p",
            "--payload",
            required=True,
            metavar="payload",
            action="store",
            help="the payload used for scanner (list: single,file)"
        )
        cliparser.add_argument(
            "-t",
            "--threads",
            type=int,
            metavar="int",
            default=50,
            help="number of concurrent threads (default: 50)"
        )
        cliparser.add_argument(
            "-pg",
            "--page-timeout",
            type=float,
            metavar="float",
            default=5,
            help="set the page load timeout (default: 5)"
        )

        return parser.parse_args()

class Scanner:

    def __init__(self, args):
        self.args = args

    @property
    def target(self):
        if not self.args.input:
            return sys.stdin.read().splitlines()
        else:
            return self.args.input.splitlines() if not os.path.isfile(self.args.input) else open(self.args.input, "r").read().splitlines()

    @property
    def payload(self):
        return self.args.payload.splitlines() if not os.path.isfile(self.args.payload) else open(self.args.payload, "r").read().splitlines()

    @property
    def page_timeout(self):
        return self.args.page_timeout
    
    @property
    def options(self):
        if self.args.mode == "gui":
            return None
        if self.args.mode == "cli":
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-gpu")

            return options

    def driver(self, option_driver):
        return webdriver.Chrome(options=option_driver)
    
    def dataTarget(self, target, payload):
        urls = []

        for url in target:
            parse = urlparse(url)
            parseQuery = parse.query.split("&")
                
            newQuery = "&".join(["{}{}".format(query, payload) for query in parseQuery])
            newParse = parse._replace(query=newQuery)

            urls.append(urlunparse(newParse).strip())

        return urls
        
    def scan_xss(self, target, payload):
        driver = self.driver(option_driver=self.options)

        for url in target:
            log_time = str(datetime.now().strftime("%H:%M:%S"))
            params = parse_qs(urlparse(url).query)
            try:
                driver.set_page_load_timeout(self.page_timeout)
                driver.get(url)
                driver.switch_to.alert.accept()
                print(f"""\033[32m
Info: fxscan identified the following injection points
Time: {str(datetime.now())}
Weakness: Cross Site Scripting (XSS)
Parameter: {", ".join(param for param in params.keys())}
    Status: Vulnerable to xss
    Target: {url}
    Payload: {payload}\033[0m
                """)
            except TimeoutException:
                print(f"[\033[36m{log_time}\033[0m] [\033[33mTIMEOUT\033[0m] \033[37m{url}\033[0m")
                continue
            except NoAlertPresentException:
                print(f"[\033[36m{log_time}\033[0m] [\033[31mFAILURE\033[0m] \033[37m{url}\033[0m")
                continue
            except UnexpectedAlertPresentException:
                print(f"""\033[35m
Info: fxscan identified the following unexpected injection points
Time: {str(datetime.now())}
Weakness: Cross Site Scripting (XSS)
Parameter: {", ".join(param for param in params.keys())}
    Status: Possible unexpected xss
    Target: {url}
    Payload: {payload}\033[0m
                """)
                continue
            except Exception:
                continue
            except KeyboardInterrupt:
                time.sleep(1)
                driver.quit()
                print("")
                break

        driver.quit()

    def scan_target(self):
        for payload in self.payload:
            self.scan_xss(target=self.dataTarget(target=self.target, payload=payload), payload=payload)

class Fxss(Options, Scanner):

    def __init__(self):
        Options.__init__(self, banner=self.print_banner)
        Scanner.__init__(self, args=self.option_parser)

    @property
    def version(self):
        return "v0.2-dev"

    @property
    def print_banner(self):
        print(r"""
      _____                                     
    _/ ____\__  ___  ______ ____ _____    ____  
    \   __\\  \/  / /  ___// ___\\__  \  /    \ 
     |  |   >    <  \___ \\  \___ / __ \|   |  \
     |__|  /__/\_ \/____  >\___  >____  /___|  /
                 \/     \/     \/     \/     \/ 
        """)
    
    @property
    def run(self):
        with ThreadPoolExecutor(max_workers=(self.args.threads)) as executor:
            try:
                executor.submit(self.scan_target)
            finally:
                executor.shutdown()

def main():
    try:
        Fxss().run
    except AttributeError:
        pass

if __name__ == '__main__':
    main()