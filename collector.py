import io
import re
import sys
import argparse
import requests
import socket
import ssl
import os
import threading
import time
import dns.resolver
from colorama import init, Fore, Style
from bs4 import BeautifulSoup
import whois
from datetime import datetime
from colorama import init, Fore, Style
import base64
from urllib.parse import urljoin
from urllib.parse import urlparse
from requests.exceptions import HTTPError



init(autoreset=True)


def display_message():
    pattern = r"""
******************************************************************************************
*___________.__             _________        .__  .__                 __                 *
*\__    ___/|  |__   ____   \_   ___ \  ____ |  | |  |   ____   _____/  |_  ___________  *
*  |    |   |  |  \_/ __ \  /    \  \/ /  _ \|  | |  | _/ __ \_/ ___\   __\/  _ \_  __ \ *
*  |    |   |   Y  \  ___/  \     \___(  <_> )  |_|  |_\  ___/\  \___|  | (  <_> )  | \/ *
*  |____|   |___|  /\___  >  \______  /\____/|____/____/\___  >\___  >__|  \____/|__|    *
*                \/     \/          \/                      \/     \/                    *
*                                                                                        *
*    Project : The Collector                                                             *
*    Coded By : Alya Almaeeli                                                            *
*    Version: 0.9                                                                        *
******************************************************************************************
    """
    # Get the width of the terminal window
    terminal_width = shutil.get_terminal_size().columns

    # Calculate the number of spaces needed to center each line
    padding = (terminal_width - max(len(line) for line in pattern.split('\n'))) // 2

    # Print each line of the pattern with green color and centered
    for line in pattern.split('\n'):
        print(Colors.GREEN + ' ' * padding + line + Colors.RESET)

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    RESET = '\033[0m'

# Function to remove ANSI escape codes for text output
def remove_ansi_escape_codes(text):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# Function to convert ANSI escape codes to HTML tags for HTML output
def convert_ansi_to_html(text):
    # Convert common ANSI codes to HTML. You may need to extend this list based on the ANSI codes you use.
    text = text.replace(Colors.GREEN, "<span style='color:green;'>").replace(Colors.RED, "<span style='color:red;'>").replace(Colors.YELLOW, "<span style='color:yellow;'>").replace(Colors.RESET, "</span>")
    text = text.replace("\n", "<br>")
    
    # Remove any remaining ANSI codes that were not converted
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    text = ansi_escape.sub('', text)

    return text
    
    
def display_colored_header(message):
    print(f"{Colors.GREEN}{message}{Colors.RESET}")

def display_warning(message):
    print(f"{Colors.YELLOW}{message}{Colors.RESET}")

def display_alert(message):
    print(f"{Colors.RED}{message}{Colors.RESET}")    
 
def format_url(domain):
    if not domain.startswith('http://') and not domain.startswith('https://'):
        domain = 'https://www.' + domain
    return domain

def get_ssl_info(hostname):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            certificate = ssock.getpeercert()
            subject = dict(x[0] for x in certificate['subject'])
            issued_to = subject.get('commonName', 'Unavailable')
            issuer = dict(x[0] for x in certificate['issuer'])
            issued_by = issuer.get('commonName', 'Unavailable')
            valid_from = datetime.strptime(certificate['notBefore'], '%b %d %H:%M:%S %Y %Z')
            valid_until = datetime.strptime(certificate['notAfter'], '%b %d %H:%M:%S %Y %Z')
            return {
                'issued_to': issued_to,
                'issued_by': issued_by,
                'valid_from': valid_from.strftime('%Y-%m-%d %H:%M:%S'),
                'valid_until': valid_until.strftime('%Y-%m-%d %H:%M:%S')
            }

def get_http_headers(url):
    response = requests.head(url)
    return response.headers

def get_whois_info(domain):
    w = whois.whois(domain)
    return {
        'domain_name': w.domain_name,
        'registrar': w.registrar,
        'whois_server': w.whois_server,
        'referral_url': w.referral_url,
        'updated_date': w.updated_date,
        'creation_date': w.creation_date,
        'expiration_date': w.expiration_date
    }

def format_dates(date):
    if isinstance(date, list):
        # If there are multiple dates, use the first one
        date = date[0]
    return date.strftime('%Y-%m-%d %H:%M:%S') if date else 'Unavailable'

def scrape_website(url, output_format, output_dir):
    response = requests.get(url)
    if output_format == 'html':
        content = response.text
        file_extension = '.html'
    else:
        content = BeautifulSoup(response.text, 'html.parser').get_text()
        file_extension = '.txt'

    domain = url.split("//")[-1].split("/")[0].replace('.', '_').replace('www_', '')
    filename = f"{domain}{file_extension}"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(content)

    print(f"Content scraped and saved to {filepath}")


global spinner_active
spinner_active = True

global spinner_thread  # Initialize spinner_thread variable outside the function scope
spinner_thread = None  # Assign None initially


def spinner_animation(message="Processing..."):
    spinner = ['-', '\\', '|', '/']
    while spinner_active:
        for char in spinner:
            if not spinner_active:
                break
            status = f"{message} {char}"
            print(status, end='\r')
            time.sleep(0.1)
    # Clear the line after the animation stops
    print(' ' * len(status), end='\r')

def display_security_info(url):

    domain = url.split("//")[-1].split("/")[0]
    ssl_info = get_ssl_info(domain)
    headers = get_http_headers(url)
    whois_info = get_whois_info(domain)

    # Start building the result string
    result = f"{Colors.GREEN}\nSSL Certificate Information :\n{Colors.RESET}"
    result += f"Issued To: {ssl_info['issued_to']}\n"
    result += f"Issued By: {ssl_info['issued_by']}\n"
    result += f"Valid From: {ssl_info['valid_from']}\n"
    result += f"Valid Until: {ssl_info['valid_until']}\n"

    result += f"{Colors.GREEN}\nHTTP Headers :\n{Colors.RESET}"
    for header, value in headers.items():
        result += f"{header}: {value}\n"

    result += f"{Colors.GREEN}\nWHOIS Information:\n{Colors.RESET}"
    result += f"Domain Name: {whois_info['domain_name']}\n"
    result += f"Registrar: {whois_info['registrar']}\n"
    result += f"WHOIS Server: {whois_info['whois_server']}\n"
    result += f"Referral URL: {whois_info['referral_url']}\n"
    result += f"Updated Date: {format_dates(whois_info['updated_date'])}\n"
    result += f"Creation Date: {format_dates(whois_info['creation_date'])}\n"
    result += f"Expiration Date: {format_dates(whois_info['expiration_date'])}\n"

    return result
    

def analyze_meta_tags(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    meta_tags = soup.find_all('meta')
    print(f"{Colors.GREEN}\nMeta Tags Information:\n{Colors.RESET}")
    for tag in meta_tags:
        if tag.get('name'):
            print(f"Name: {tag.get('name')}, Content: {tag.get('content')}")
        elif tag.get('property'):
            print(f"Property: {tag.get('property')}, Content: {tag.get('content')}")
            


def scrape_images(url, output_dir):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}Error occurred while fetching URL: {e}{Colors.RESET}")
        return

    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Step 1: Extract image URLs from HTML
    image_tags = soup.find_all('img')
    image_urls = [img['src'] for img in image_tags if img.get('src')]
    
    # Step 2: Extract image URLs from linked CSS files
    css_links = [link['href'] for link in soup.find_all('link', rel='stylesheet')]
    for css_link in css_links:
        css_url = urljoin(url, css_link)
        css_response = requests.get(css_url)
        css_content = css_response.text
        css_image_urls = extract_css_image_urls(css_content)
        image_urls.extend(css_image_urls)
    
    # Step 3: Extract image URLs from linked JavaScript files
    js_links = [script['src'] for script in soup.find_all('script') if script.get('src')]
    for js_link in js_links:
        js_url = urljoin(url, js_link)
        js_response = requests.get(js_url)
        js_content = js_response.text
        js_image_urls = extract_js_image_urls(js_content)
        image_urls.extend(js_image_urls)
    
    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Step 4: Download images
    for index, img_url in enumerate(image_urls):
        try:
            # Skip malformed URLs
            if not img_url.startswith(('http://', 'https://')):
                print(f"{Colors.BLUE}Skipping malformed URL: {img_url}{Colors.RESET}")
                continue
            
            # Check if the URL is a base64-encoded string
            if img_url.startswith('data:image'):
                # Decode base64 string and save the image
                img_data = base64.b64decode(img_url.split(';base64,')[-1])
                img_filename = f"base64_image_{index}.png"
            else:
                img_response = requests.get(img_url)
                img_response.raise_for_status()  # Raise an exception for HTTP errors
                img_data = img_response.content
                
                # Extract the filename from the URL and remove query parameters
                img_filename = os.path.basename(img_url.split('?')[0])
            
            # Save the image with the correct extension
            img_path = os.path.join(output_dir, img_filename)
            with open(img_path, 'wb') as img_file:
                img_file.write(img_data)
                
            print(f"{Colors.GREEN}Image downloaded and saved to: {img_path}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error downloading image from {img_url}: {e}{Colors.RESET}")

    print(f"{Colors.GREEN}\nImages Downloaded and Saved to {output_dir}\n{Colors.RESET}")



# Function to extract image URLs from CSS content
def extract_css_image_urls(css_content):
    # Use regular expressions or a CSS parser library to extract URLs from CSS content
    # Example using regular expressions:
    return re.findall(r'url\((.*?)\)', css_content)


# Function to extract image URLs from JavaScript content
def extract_js_image_urls(js_content):
    # Use regular expressions or a JavaScript parser library to extract URLs from JavaScript content
    # Example using regular expressions:
    return re.findall(r'["\']((?:https?:\/\/|\/)\S+?\.(?:png|jpe?g|gif))["\']', js_content)



def scrape_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    all_links = soup.find_all('a', href=True)
    internal_links = [link['href'] for link in all_links if not link['href'].startswith('http')]
    external_links = [link['href'] for link in all_links if link['href'].startswith('http')]
    print(f"{Colors.GREEN}\nInternal Links:\n{internal_links}\n\nExternal Links:\n{external_links}\n{Colors.RESET}")

def analyze_social_media_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    social_media_links = [a['href'] for a in soup.find_all('a', href=True) if 'facebook.com' in a['href'] or 'twitter.com' in a['href'] or 'instagram.com' in a['href']] 
    print(f"{Colors.GREEN}\nSocial Media Links:\n{social_media_links}\n{Colors.RESET}")

def fetch_robots_txt(url):
    try:
        response = requests.get(url + '/robots.txt')
        print(f"{Colors.GREEN}\nRobots.txt:\n{response.text}\n{Colors.RESET}")
    except:
        print(f"{Colors.RED}\nFailed to Fetch Robots.txt\n{Colors.RESET}")

def fetch_sitemap(url):
    try:
        response = requests.get(url + '/sitemap.xml')
        print(f"{Colors.GREEN}\nSitemap.xml:\n{response.text}\n{Colors.RESET}")
    except:
        print(f"{Colors.RED}\nFailed to Fetch Sitemap.xml\n{Colors.RESET}")

def measure_page_load_speed(url):
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    load_time = end_time - start_time
    print(f"{Colors.GREEN}\nPage Load Speed: {load_time} seconds\n{Colors.RESET}")

def analyze_security_headers(url):
    response = requests.get(url)
    security_headers = response.headers.get('Content-Security-Policy'), response.headers.get('X-Frame-Options'), response.headers.get('X-XSS-Protection')
    print(f"{Colors.GREEN}\nSecurity Headers:\nContent-Security-Policy: {security_headers[0]}\nX-Frame-Options: {security_headers[1]}\nX-XSS-Protection: {security_headers[2]}\n{Colors.RESET}")


# Function to capture print statements and return them as a string
def capture_and_print(func, *args, **kwargs):
    # Capture the function's output
    captured_output = io.StringIO()
    sys.stdout = captured_output
    func(*args, **kwargs)
    sys.stdout = sys.__stdout__  # Reset stdout to original

    # Get the captured output and print it
    output = captured_output.getvalue()
    print(output, end='')  # Print the captured output

    return output

# Adjust the export_results function
def export_results(results, export_format, directory, filename="results"):
    filepath = os.path.join(directory, f"{filename}.{export_format}")

    if export_format == 'html':
        # Convert ANSI codes to HTML tags for HTML output
        results = f"<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n<title>Results</title>\n</head>\n<body>\n{convert_ansi_to_html(results)}\n</body>\n</html>"
    else:
        # Remove ANSI codes for text output
        results = remove_ansi_escape_codes(results)

    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(results)
    
    print(f"Results exported to {filepath}")

def start_spinner():
    global spinner_active
    global spinner_thread
    spinner_active = True
    spinner_thread = threading.Thread(target=spinner_animation, args=("Processing...",))
    spinner_thread.start()
    return spinner_thread

def check_sri(url):
    result = f"{Colors.GREEN}\nSubresource Integrity (SRI) Check:\n{Colors.RESET}"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all script and link tags with integrity attribute (SRI implemented)
    resources_with_sri = soup.find_all(lambda tag: (tag.name == 'script' or (tag.name == 'link' and 'stylesheet' in tag.get('rel', []))) and tag.has_attr('integrity'))
    
    # Find all script and link tags without integrity attribute (SRI not implemented)
    resources_without_sri = soup.find_all(lambda tag: (tag.name == 'script' or (tag.name == 'link' and 'stylesheet' in tag.get('rel', []))) and not tag.has_attr('integrity') and (tag.get('src') or tag.get('href')))

    if resources_with_sri:
        result += "Resources with Subresource Integrity (SRI) detected. This is good for security.\n"
    else:
        result += "All external resources passed the Subresource Integrity (SRI) check.\n"

    if resources_without_sri:
        result += f"{Colors.YELLOW}Resources without SRI (consider adding SRI for better security):\n"
        for resource in resources_without_sri:
            src = resource.get('src') or resource.get('href')
            result += f"Resource without SRI: {src}\n"
    else:
        result += "No resources found without Subresource Integrity.\n"


    return result

def analyze_csp(url):
    result = f"{Colors.GREEN}\nContent Security Policy (CSP) Check:\n{Colors.RESET}"
    response = requests.get(url)
    
    if 'Content-Security-Policy' in response.headers:
        csp = response.headers['Content-Security-Policy']
        result += f"{Colors.GREEN}Content-Security-Policy is set: {csp}{Colors.RESET}\n"
        # Further analysis and additions to result...
    else:
        result += f"{Colors.RED}No Content-Security-Policy set. It's recommended to define a CSP for better security.{Colors.RESET}\n"
    
    return result

def analyze_feature_policy(url):
    result = ""
    response = requests.get(url)
    policy_header = 'Permissions-Policy' if 'Permissions-Policy' in response.headers else 'Feature-Policy'
    
    result += f"{Colors.GREEN}\n{policy_header} Check:\n{Colors.RESET}"
    
    if policy_header in response.headers:
        policy = response.headers[policy_header]
        result += f"{Colors.GREEN}{policy_header} is set: {policy}{Colors.RESET}\n"
        # Additional detailed analysis as needed
    else:
        result += f"{Colors.RED}No {policy_header} set. It's recommended to define a {policy_header} for better security.{Colors.RESET}\n"

    
    return result

def analyze_email_security(domain):
    result = f"{Colors.GREEN}\nEmail Security Checks:\n{Colors.RESET}"

    # Check SPF record
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = [str(r.to_text()) for r in answers if "v=spf1" in str(r.to_text())]
        if spf_record:
            result += f"{Colors.GREEN}SPF record found: {spf_record[0]}{Colors.RESET}\n"
        else:
            result += f"{Colors.RED}No SPF record found. It's recommended to have an SPF record for better email security.{Colors.RESET}\n"
    except Exception as e:
        result += f"{Colors.RED}Error fetching SPF record: {e}{Colors.RESET}\n"

   
    return result

def scan_mixed_content(url):
    if not url.startswith('https'):
        return "Mixed Content Scan is only relevant for HTTPS pages."
    
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    mixed_content = []

    for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
        src_attr = 'href' if tag.name == 'link' else 'src'
        if src_attr in tag.attrs and tag.attrs[src_attr].startswith('http://'):
            mixed_content.append(tag.attrs[src_attr])
    
    results = "Mixed Content Scan Results:\n"
    for content in mixed_content:
        results += f"- {content}\n"
    
    return results


if __name__ == "__main__":
    display_message()
    parser = argparse.ArgumentParser(description="Get security information for a website and/or scrape its content.")
    parser.add_argument("-w", "--website", type=str, required=True, help="Specify the website domain")
    parser.add_argument("-s", "--security", action="store_true", help="Fetch security information")
    parser.add_argument("-r", "--scrape", action="store_true", help="Scrape the website content")
    parser.add_argument("-t", "--type", type=str, choices=['txt', 'html'], default='txt', help="Specify the output format for scraping")
    parser.add_argument("-d", "--directory", type=str, default='.', help="Specify the directory to save the scraped content")
    parser.add_argument("-c", "--csp", action="store_true", help="Analyze the website's Content Security Policy")
    parser.add_argument("-i", "--sri", action="store_true", help="Check for Subresource Integrity in website resources")
    parser.add_argument("-p", "--policy", action="store_true", help="Analyze Feature Policy header to identify which features are enabled or disabled.")
    parser.add_argument("-e", "--email", action="store_true", help="Analyze the website's domain for SPF, DKIM, and DMARC records to assess its email security posture.")
    parser.add_argument("--export", action="store_true", help="Export the results to a file.")
    parser.add_argument("--mixed-content-scan", action="store_true", help="Scan for mixed content on the webpage")
    parser.add_argument("--meta-tags", action="store_true", help="Scrape and analyze meta tags of the webpage")
    parser.add_argument("--images", action="store_true", help="Download images from the webpage")
    parser.add_argument("--links", action="store_true", help="Scrape and analyze internal and external links of the webpage")
    parser.add_argument("--social-media", action="store_true", help="Analyze social media links present on the webpage")
    parser.add_argument("--robots-txt", action="store_true", help="Fetch and analyze the robots.txt file of the website")
    parser.add_argument("--sitemap", action="store_true", help="Fetch and analyze the sitemap.xml file of the website")
    parser.add_argument("--structured-data", action="store_true", help="Analyze structured data present on the webpage")
    parser.add_argument("--page-load-speed", action="store_true", help="Measure the page load speed of the website")
    parser.add_argument("--security-headers", action="store_true", help="Analyze security headers of the website")

    args = parser.parse_args()
    actions = [args.security, args.scrape, args.csp, args.sri, args.policy, args.email, args.meta_tags, args.images, args.links,
               args.social_media, args.robots_txt, args.sitemap, args.structured_data, args.page_load_speed, args.security_headers]
   
    if args.website and any(actions):
        spinner_thread = start_spinner()  # Start the spinner only when needed
        
    if args.website:
        url = format_url(args.website)
        results_to_export = ""

        if args.security:
            security_info = display_security_info(args.website)
            security_info = security_info if security_info else ""  # Convert None to empty string if necessary
            print(security_info)  # Display results on CLI
            results_to_export += security_info  # Collect results for export

        if args.scrape:
            # Assuming scrape_website function handles its own printing and file writing
            scrape_website(url, args.type, args.directory)

        if args.csp:
            csp_info = analyze_csp(url)
            csp_info = csp_info if csp_info else ""  # Convert None to empty string if necessary
            print(csp_info)
            results_to_export += csp_info

        if args.sri:
            sri_info = check_sri(url)
            sri_info = sri_info if sri_info else ""  # Convert None to empty string if necessary
            print(sri_info)
            results_to_export += sri_info

        if args.policy:
            policy_info = analyze_feature_policy(url)
            policy_info = policy_info if policy_info else ""  # Convert None to empty string if necessary
            print(policy_info)
            results_to_export += policy_info

        if args.email:
            email_info = analyze_email_security(url)
            email_info = email_info if email_info else ""  # Convert None to empty string if necessary
            print(email_info)
            results_to_export += email_info

        if args.mixed_content_scan:
            mixed_content_info = scan_mixed_content(url)
            mixed_content_info = mixed_content_info if mixed_content_info else ""  # Convert None to empty string if necessary
            print(mixed_content_info)
            results_to_export += mixed_content_info

        if args.meta_tags:
            meta_tags_info = analyze_meta_tags(url)
            meta_tags_info = meta_tags_info if meta_tags_info else ""  # Convert None to empty string if necessary
            print(meta_tags_info)
            results_to_export += meta_tags_info

        if args.images:
            scrape_images(url, args.directory)

        if args.links:
            scrape_links(url)

        if args.social_media:
            analyze_social_media_links(url)

        if args.robots_txt:
            fetch_robots_txt(url)

        if args.sitemap:
            fetch_sitemap(url)

        if args.page_load_speed:
            measure_page_load_speed(url)

        if args.security_headers:
            analyze_security_headers(url)

        if args.export:
            export_results(results_to_export, 'txt', args.directory)

        if spinner_thread is not None:  # Check if spinner_thread is not None before joining
           spinner_active = False
           spinner_thread.join()  # Wait for the spinner thread to finish
