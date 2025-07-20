import os
import csv
import json
import logging
import chardet
from git import Repo
from git.exc import GitCommandError
from pathlib import Path
from typing import List, Dict, Optional  # Import Optional here

# Configuration
CSV_FILE = 'Test_IP.csv'
OUTPUT_FILE = 'Test_dataset.csv'
CLONED_REPOS_DIR = 'cloned_repos'
VALID_EXTENSIONS = ['.java', '.py', '.js', '.c', '.cpp', '.h', '.go']
MIN_CODE_LENGTH = 50  # Minimum lines of code to consider
MAX_FILE_SIZE = 100000  # 100KB max file size

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('extraction.log'),
        logging.StreamHandler()
    ]
)

def get_file_content(repo_path: str, file_path: str, commit_hash: str) -> Optional[str]:
    """Extract file content from a specific commit with proper encoding handling"""
    try:
        repo = Repo(repo_path)
        commit = repo.commit(commit_hash)
        blob = commit.tree[file_path]
        
        # Skip large files
        if blob.size > MAX_FILE_SIZE:
            return None
            
        raw_data = blob.data_stream.read()
        encoding = chardet.detect(raw_data)['encoding'] or 'utf-8'
        content = raw_data.decode(encoding, errors='replace')
        
        # Basic validation
        lines = content.splitlines()
        if len(lines) < MIN_CODE_LENGTH:
            return None
            
        return content
    except Exception as e:
        logging.warning(f"Error reading {file_path} at {commit_hash}: {str(e)}")
        return None

def process_repository(repo_url: str, cve_id: str, commit_hash: str) -> List[Dict]:
    """Process a repository to extract vulnerable/fixed code pairs"""
    repo_name = repo_url.split('/')[-1].replace('.git', '')
    repo_path = os.path.join(CLONED_REPOS_DIR, repo_name)
    results = []

    try:
        # Clone repository if needed
        if not os.path.exists(repo_path):
            logging.info(f"Cloning {repo_url}")
            Repo.clone_from(repo_url, repo_path)

        repo = Repo(repo_path)
        commit = repo.commit(commit_hash)
        
        if not commit.parents:
            logging.warning(f"No parent commit for {commit_hash}")
            return []

        parent_commit = commit.parents[0]
        
        # Get changed files between parent (vulnerable) and child (fixed)
        diff = parent_commit.diff(commit)
        
        for diff_item in diff:
            if diff_item.change_type != 'M':
                continue
                
            file_path = diff_item.a_path
            if Path(file_path).suffix.lower() not in VALID_EXTENSIONS:
                continue

            # Get both versions of the code
            vulnerable_code = get_file_content(repo_path, file_path, parent_commit.hexsha)
            fixed_code = get_file_content(repo_path, file_path, commit_hash)
            
            if not vulnerable_code or not fixed_code:
                continue
                
            if vulnerable_code == fixed_code:
                continue

            # Add to results with proper labels
            results.append({
                "cve_id": cve_id,
                "file_path": file_path,
                "code": vulnerable_code,
                "label": 0  # Vulnerable version
            })
            results.append({
                "cve_id": cve_id,
                "file_path": file_path,
                "code": fixed_code,
                "label": 1  # Fixed version
            })

    except Exception as e:
        logging.error(f"Error processing {repo_url}: {str(e)}")
    
    return results

def main():
    os.makedirs(CLONED_REPOS_DIR, exist_ok=True)
    
    # Clear output file
    with open(OUTPUT_FILE, 'w') as f:
        pass
    
    # Process each CVE entry
    with open(CSV_FILE, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_id = row['cve_id']
            repo_url = row['repo_url'].strip()
            commit_hash = row['commit_hash'].strip()
            
            if not repo_url or not commit_hash:
                continue
                
            logging.info(f"Processing {cve_id} from {repo_url}")
            
            # Get vulnerable/fixed pairs
            pairs = process_repository(repo_url, cve_id, commit_hash)
            
            # Append to output file
            with open(OUTPUT_FILE, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["cve_id", "file_path", "code", "label"])
                if f.tell() == 0:
                    writer.writeheader()
                for pair in pairs:
                    writer.writerow(pair)
            
            logging.info(f"Extracted {len(pairs)//2} code pairs for {cve_id}")

if __name__ == "__main__":
    main()