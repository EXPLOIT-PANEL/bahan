#bin/python3
#bingung mau pake bahasa apa jdi pake campur aja lahh :v
#agar orang indo bisa bahasa en yang bahasa en bisa ngerti bahasa id
#warning powerful tools xploiter can be harmful and detrimental
#GUNAKAN TOOLS INI UNTUK TUJUAN KEBAIKAN MEMBANTU PANTESTING
#BUKAN UNTUK MERUSAK SEGALA SEUSATU DI TANGGUNG PENGGUNA

import os 
import phonenumbers 
from Settings.Program.Config import randomuser
from rich.panel import Panel
from rich.tree import Tree
from rich import print as prints
from rich.console import Console
from rich import print as cetak
from rich.table import Table
from rich.columns import Columns
from rich.progress import Progress,SpinnerColumn,BarColumn,TextColumn,TimeElapsedColumn
import re, sys, json, httpx, random, urllib, hmac, hashlib, time, string, uuid, requests, base64, webbrowser, datetime, names, shutil, socket, wget, ipaddress, asyncio, aiohttp, subprocess, threading
from Settings.Program.Config.Util import *
from pystyle import Write, Colors, Box, Center, Colorate
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from googlesearch import search
from colorama import Fore, Back, Style, init
from concurrent.futures import ThreadPoolExecutor as ThreadPoolExec
from rich.progress import Progress,SpinnerColumn,BarColumn,TextColumn,TimeElapsedColumn
from rich.tree import Tree
from datetime import datetime
from rich import print as sprint
from rich.console import Console
from rich.panel import Panel as panel
from getpass import getpass
from googlesearch import search 
from rich.columns import Columns
from requests.exceptions import ConnectionError
from multiprocessing import Pool
from subprocess import getoutput
from os.path import exists
import urllib.request 
from urllib.parse import urlparse
from urllib.parse import quote_plus
from pytube import YouTube
from multiprocessing.dummy import Pool
from collections import deque
from queue import Queue
from tqdm import tqdm

class HashCracker:
    def __init__(self, hash_type, hash_to_crack, wordlist, custom_hash=None, verbose=False, silent=False, salt=None, output_file="result/result_hash.txt", exit_on_found=False):
        self.hash_type = hash_type
        self.hash_to_crack = hash_to_crack
        self.wordlist = wordlist
        self.silent = ""
        self.salt = ""
        self.verbose = ""
        self.custom_hash = custom_hash
        self.output_file = output_file
        self.found = threading.Event()
        self.queue = Queue()

    def hash_word(self, word):
        try:
            if self.custom_hash:
                return self.custom_hash(word)
            if self.hash_type == 'MD5':
                return hashlib.md5(word.encode()).hexdigest()
            elif self.hash_type == 'SHA1':
                return hashlib.sha1(word.encode()).hexdigest()
            elif self.hash_type == 'SHA224':
                return hashlib.sha224(word.encode()).hexdigest()
            elif self.hash_type == 'SHA256':
                return hashlib.sha256(word.encode()).hexdigest()
            elif self.hash_type == 'SHA384':
                return hashlib.sha384(word.encode()).hexdigest()
            elif self.hash_type == 'SHA512':
                return hashlib.sha512(word.encode()).hexdigest()
            elif self.hash_type == 'SHA3-224':
                return hashlib.sha3_224(word.encode()).hexdigest()
            elif self.hash_type == 'SHA3-256':
                return hashlib.sha3_256(word.encode()).hexdigest()
            elif self.hash_type == 'SHA3-384':
                return hashlib.sha3_384(word.encode()).hexdigest()
            elif self.hash_type == 'SHA3-512':
                return hashlib.sha3_512(word.encode()).hexdigest()
            elif self.hash_type == 'RIPEMD160':
                return hashlib.new('ripemd160', word.encode()).hexdigest()
            elif self.hash_type == 'Whirlpool':
                return hashlib.new('whirlpool', word.encode()).hexdigest()
            elif self.hash_type == 'BLAKE2b':
                return hashlib.blake2b(word.encode()).hexdigest()
            elif self.hash_type == 'BLAKE2s':
                return hashlib.blake2s(word.encode()).hexdigest()
            else:
                print(f"Hash type {self.hash_type} is not supported.")
                return None
        except Exception as e:
            print(f"Error in hash_word: {e}")
            return None

    def load_wordlist(self):
        try:
            with open(self.wordlist, 'r', errors='ignore') as file:
                return [line.strip() for line in file if not self.found.is_set()]
        except Exception as e:
            print(f"{M}Error loading wordlist: {e}")
            return []

    def worker(self):
        while not self.queue.empty() and not self.found.is_set():
            word = self.queue.get()
            if self.salt:
                word = self.salt + word
            hashed_word = self.hash_word(word)
            if self.verbose and not self.silent:
                print(f"Trying {word}: {hashed_word}")
            if hashed_word == self.hash_to_crack:
                self.found.set()
                if not self.silent:
                    print(f"{M}[{P}+{M}] {H}Password found: {P}{word}")
                if self.output_file:
                    try:
                        with open(self.output_file, 'a') as result_file:
                            result_file.write(f"{self.hash_to_crack}:{word}\n")
                    except Exception as e:
                        print(f"Error writing to output file: {e}")
                break
            self.queue.task_done()

    def crack(self, num_threads=1000):
        words = self.load_wordlist()
        if not words:
            return
        if not self.silent:
            print(f"{M}[{P}+{M}] {B}Total words to try: {P}{len(words)}")

        for word in words:
            self.queue.put(word)

        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)
        
        with tqdm(total=len(words), disable=False) as pbar:
            while not self.queue.empty() and not self.found.is_set():
                pbar.update(1)
        
        for thread in threads:
            thread.join()

def detect_hash_type(hash_value):
    try:
        hash_lengths = {
            32: 'MD5',
            40: 'SHA1',
            56: 'SHA224',
            64: 'SHA256',
            96: 'SHA384',
            128: 'SHA512',
        }
        return hash_lengths.get(len(hash_value), None)
    except Exception as e:
        print(f"{M}Error in detect_hash_type: {P}{e}")
        return None

def Hash_Cracker():
    wordlist_path = "Data/wordlist_hash.txt"   
    hash_type = "AUTO"
    hash_to_crack = input(f"{M}[{P}+{M}] {B}Input hash : {P}")
    custom_hash = None
    output_file = "result/result_hash.txt"
    detected_type = detect_hash_type(hash_to_crack)
    if detected_type:
        print(f"{K}Detected hash type: {P}{detected_type}")
        hash_cracker = HashCracker(detected_type, hash_to_crack, wordlist_path, custom_hash=custom_hash, output_file=output_file)
        hash_cracker.crack()
    else:
        print(f"{M}Unable to detect hash type. Please specify the hash type explicitly.")
        
def data2():
    target = input(f"{M}[{P}+{M}] {B}Enter Target Sites : ")
    print(f'{M}[{P}+{M}]{K} Processing....')
    file_types = ['pdf', 'doc', 'rar', 'txt', 'dta', 'ppt', 'shx', 'pptx', 'dbf', 'shp', 'db', 'mdf', 'mpd', 'ndb', 'docx', 'docm', 'dot', 'dotx', 'dotm','csv', 'xls', 'xlsx', 'xslsm', 'xlt', 'xltx', 'xltm', 'sql', 'zip', 'rar4', 'xyz']
    
    resultdork = ""
    for i in file_types:
        try:
            cookies = exists('.google-cookie')
            if cookies == True:
                os.remove('.google-cookie')
            print("")
            print(M + 33*"═")
            print(f"{B}File Types :{K} {i}")
            print(M + 33*"═")
            print("")
            for results in search(f'site:{target} filetype:{i}', tld='com', num=5, start=0, stop=None, pause=20):
                print(f"{M}[{P}+{M}] {B}Found : " + H + results)
                def log(target):
                    file = open((target) + ".txt", "a")
                    file.write(str(results))
                    file.write("\n")
                    file.close
                    file_name = target
                log(target)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print(M + f'[429] Too Many Request, Please Wait')
                time.sleep(15)
        except KeyboardInterrupt:
            print(f"{M}[{P}+{M}] {M}File Extension :{B} {i} {M}Skipped.. [{P}+{M}]")
            continue
    print(f"{M}[{P}+{M}] {H}Done... {M}[{P}+{M}]")

def mail():
    user_url = str(input(f'{M}[{P}+{M}] {B}Enter Url (use http/https) : {P}'))
    usurl = user_url
    urls = deque([usurl])
    scraped_urls = set()
    emails = set()
    count = 0
    limit = int(input(f"{M}[{P}+{M}] {B}Limit : {P}"))
    
    try:
      while True:
        count += 1
        if count > limit:
          break
        
        url = urls.popleft()
        scraped_urls.add(url)
        parts = urllib.parse.urlsplit(url)
        base_url = f'{parts.scheme}://{parts.netloc}'
        path = url[:url.rfind('/')+1] if '/' in parts.path else url 
        print(f'{M}[{P}{count}{M}] {K}Processing ->{B} {url}')
        
        try:
          response = requests.get(url)
        except(requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
          continue
        
        new_emails = set(re.findall(r'[a-z0-9\.\-+_]+@\w+\.+[a-z\.]+', response.text, re.I))
        emails.update(new_emails)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        for anchor in soup.find_all('a'):
          link = anchor.attrs['href'] if 'href' in anchor.attrs else ''
          if link.startswith('/'):
            link = base_url + link
          elif not link.startswith('http'):
            link = path + link
          if not link in urls and not link in scraped_urls:
            urls.append(link)
    except KeyboardInterrupt:
      print('closing')
      
    print(f'\n{M}[{P}+{M}]{H} Proses selesai {M}[{P}+{M}]{H}')
    print(f'{len(emails)} Email Ditemukan')
    for mail in emails:
      print(O + ' ' + mail)
    print("\n")


class Domain:
    def __init__(self, domain):
        self.domain = domain
    
    def checkShell(self):
        shellFiles = open('Data/shell.txt', 'r')
        for path in shellFiles:
            path = path.replace('\n', '')
            r = requests.get("https://"+self.domain+path)
            if "drwxr" in r.text:
                print("\x1b[1;94m[{}{}] \x1b[1;92m-> Found Shell!".format(self.domain, path))
                saveres = open("result/shellz.txt", "a")
                saveres.write(self.domain+path+'\n')
            else:
                print("\x1b[1;94m[{}{}] \x1b[1;91m-> Shell not Found!".format(self.domain, path))

def asuna(list):
    website = Domain(list)
    website.checkShell()

def shell():
    try:
        urList = open(input(f"{M}[{P}+{M}] {B}Enter Website List (ex. 2.txt) :{P} "), "r").read().split("\n")
        thread = int(input(f"{M}[{P}+{M}] {B}Enter Threads : {P}"))
        pool = Pool(thread)
        pool.map(asuna, urList)
        pool.close()
        pool.join
    except:
        pass

def Malware():
    wedus()
    print(f"{O}[{P}01{O}] {P} MALWARE V1\n{O}[{P}02{O}] {P} MALWARE V2\n{O}[{P}03{O}] {P} MALWARE V3\n{O}[{P}04{O}] {P} MALWARE V4\n{O}[{P}05{O}] {P} MALWARE V5\n{O}[{P}06{O}] {P} MALWARE V6\n{O}[{P}07{O}] {P} MALWARE V7\n{O}[{P}08{O}] {P} MALWARE V8\n")
    ______________________________________ = input(f"{B}Select Menu ->{P}")
    if ______________________________________ in["1","01"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV1"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
    
    elif ______________________________________ in["2","02"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV2"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
    elif ______________________________________ in["3","03"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV3"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
    elif ______________________________________ in["4","04"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV4"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
    elif ______________________________________ in["5","05"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV5"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
    elif ______________________________________ in["5","05"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV5"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
    elif ______________________________________ in["6","06"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV6"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
    elif ______________________________________ in["7","07"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV7"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
    elif ______________________________________ in["8","08"]:
        file_name1 = input(f"{M}[{P}+{M}] {B}Input File Name : ")

        old_name = "./Malware/MALWAREV8"
        new_name = f"./Malware/{file_name1}.exe"
        
        if os.path.isfile(new_name):
            print(f"{M}File name already exists. Cannot Create")
        else:
            # Rename the file
            os.rename(old_name, new_name)
        print(f"{K}Creating...")
        time.sleep(20)
        print(f"{M}[{P}+{M}] {H}File Malware {P}{file_name1} {H}Has Been Created. Saved In {P}Malware/{file_name1}.exe!")
        print(f"{M}Warning!, Dont you dare to click / open the file !")
def admin_finder():
    print(f"""
                ⣀⣤⣤⠶⠶⠚⠛⠛⠛⠛⠛⠛⠛⠷⠶⢦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⠞⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⢶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⡾⠋⠀⠀⠀⠀⣀⠄⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⡤⠤⠤⢤⣤⣀⡀⠀⠀⠀⠀⠀⠀⢄⡀⠀⠀⠀⠈⠻⣆⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣴⠏⠀⢀⣀⣠⣶⠟⠁⠀⠀⠀⣠⠴⠀⢀⠔⠋⢁⠎⠀⡇⠘⡄⠉⠲⣍⠑⠢⢄⡀⠀⠀⠀⠙⣷⣦⣤⡀⠀⠙⣷⡀⠀⠀⠀
⠀⠀⢀⣾⠃⠀⣴⠏⣼⡿⣣⠀⠀⢀⡴⠋⠠⢄⡴⠃⠀⠀⡞⠀⠀⠃⠀⠹⡄⠀⠈⢳⡀⠤⠘⠢⡀⠀⠀⢾⢻⣷⡘⣦⡀⠈⢿⡄⠀⠀
⠀⠀⣾⠁⣠⢺⣿⢘⣭⣾⠃⠀⡰⠋⠀⠀⢀⡜⠁⠁⠀⢺⠀⣴⣞⡳⣶⡄⠁⠀⠉⠀⠱⡄⠀⠀⠈⠢⡀⠈⢷⣬⡓⢻⣷⢦⠈⢿⡄⠀
⠀⣼⠃⢰⡇⢸⣷⡿⢻⠁⢀⠞⠀⠀⠀⠀⡜⠀⠀⠀⠀⠈⠀⠈⠁⣷⠿⠃⠀⠀⠀⠀⠀⢱⡀⠀⠀⠀⠱⡄⠀⢿⢿⣾⡿⢸⣧⠈⣷⠀
⢠⡟⠀⣾⣿⢸⣫⣶⠇⠀⡞⠀⠀⠒⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡃⠀⠀⠀⠀⠀⠀⠀⠀⠃⠠⠀⠀⠀⢹⡀⠘⣷⣌⠧⢸⣿⠀⢸⡇
⣼⡇⣰⢻⣿⣸⡿⠋⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠻⠿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⢸⣿⣧⣼⡿⢀⠀⣷
⣿⠀⣿⡀⢿⡟⢡⡇⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠸⣆⠻⣿⠃⣼⠀⢿
⣿⠀⢿⣷⠘⢰⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⡟⠀⣹⣯⡁⢸⣷⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡁⠀⢿⣦⠙⣼⣿⠀⢸
⣿⠀⠘⣿⣇⣿⡏⡄⠀⣄⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⠃⠀⢰⣇⠀⠀⣿⣿⣿⣿⣿⣷⡆⠀⠀⠀⠀⠀⢸⠁⢀⠸⣿⢰⣿⠇⠀⣾
⢻⡇⣷⡈⢻⣿⢀⣿⠀⢸⡀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⢸⣿⠀⢠⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⡾⠀⣼⡆⢿⡿⠃⣼⠀⣿
⠘⣧⠘⣿⣦⡙⢸⣿⣦⡀⢣⠀⡠⠤⠒⣿⣿⣿⣿⣿⣿⣿⣿⡄⢸⣿⢀⣾⣿⣿⣿⣿⣿⣿⣿⠒⠢⠤⣀⣰⠁⡰⣿⡇⢚⣴⣾⠏⢸⡇
⠀⢻⡄⢈⠻⣿⣼⣿⡇⣷⡈⢦⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⡰⢃⣼⠁⣿⣧⣾⡿⡃⢀⡿⠀
⠀⠈⢿⡀⢷⣌⠛⢿⣧⢸⣷⡀⠑⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠜⠁⣼⡟⢸⡿⠟⣉⡴⠃⣼⠃⠀
⠀⠀⠈⢿⡄⠻⢿⣶⣬⣁⢿⣧⢳⣄⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣠⡖⣹⣿⢃⣥⣴⣾⠟⢁⣼⠃⠀⠀
⠀⠀⠀⠈⢻⣆⠀⢝⠻⠿⢿⣿⣦⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣰⣿⡿⠿⠟⣋⠁⢠⡾⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⡀⠙⠶⣶⣤⣤⣥⣬⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣭⣼⣥⣤⣶⡶⠛⢁⣴⠟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠻⢦⣀⠀⢭⣉⣙⣉⣉⣁⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣌⣉⣉⣋⣉⡩⠁⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠷⣤⡈⠙⠛⠻⠛⠛⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⠛⠛⠛⠛⢉⣠⡶⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣦⣄⣀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢀⣀⣤⠶⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
""")
    website_url = input(f"\n{M}[{P}+{M}] {O}Target Site [Use http/https]: {P}")
    admin_paths = ['/admin/', '/admin/dashboard/', '/admin/login.php/', '/wp-admin/', '/login.php/', '/wp-admin.php/', '/wp-admin/index.php', '/admin/dashboard.html/', '/admin.html/', '/admin/', '/usuarios/', '/cpanel.php/', '/cpanel/', '/cpanel.htm/', '/controlpanel/', '/admin/upload.php/', '/wp-login.php/', '/administrator/', '/admin/add.php/', '/dashboard/', '/admin/dashboard/', '/admin/dashboard.php/', '/panel/', '/admin/panel/', '/adminpanel/', '/admin/controlpanel/', '/admin/cpanel/', '/admin/dashboard.php/', '/admin.html/', '/admin.php/', '/admin/cpanel.php/', '/admin/cp.php/', '/adm', '/administrator/index.html', '/panelcontrol', '/dash', '/admin/dash.php']
    
    for result in admin_paths:
        file_exists = ('.google-cookie')
        if file_exists == True:
            os.remove(file
