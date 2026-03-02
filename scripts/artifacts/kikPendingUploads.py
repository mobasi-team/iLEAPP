#!/usr/bin/env python3

import os
import shutil
import xml.etree.ElementTree as ET
import hashlib
from urllib.parse import quote

from scripts.artifact_report import ArtifactHtmlReport
from scripts.html_security import escape_attr, sanitize_url
from scripts.ilapfuncs import logfunc, tsv


def _find_pending_media_file(files_found, content_id):
    normalized_content = str(content_id or '').replace('\\', '/').lstrip('/')
    if not normalized_content:
        return None

    basename = os.path.basename(normalized_content)
    strong_match = None
    weak_matches = []
    for candidate in files_found:
        candidate_path = str(candidate).replace('\\', '/')
        if '/data_cache/' not in candidate_path:
            continue
        if candidate_path.endswith('/' + normalized_content):
            strong_match = candidate
            break
        if os.path.basename(candidate_path) == basename:
            weak_matches.append(candidate)

    if strong_match:
        return strong_match
    if weak_matches:
        return sorted(weak_matches)[0]
    return None


def _copy_pending_media_file(source_path, report_folder):
    basename = os.path.basename(str(source_path))
    digest = hashlib.sha1(str(source_path).encode('utf8', errors='ignore')).hexdigest()[:10]
    copied_name = f'{digest}_{basename}'
    destination_path = os.path.join(report_folder, copied_name)
    if not os.path.exists(destination_path):
        shutil.copy2(source_path, destination_path)
    return copied_name


def _build_pending_file_thumb(copied_name, content_id=None):
    # Keep a 2-argument signature for compatibility with older tests/helpers.
    if content_id is not None:
        copied_name = content_id

    if not copied_name:
        return ''

    normalized_src = sanitize_url(copied_name, allow_file=False)
    safe_src = '#' if normalized_src == '#' else quote(normalized_src)

    return f'<img src="{escape_attr(safe_src)}" width="300"></img>'


def get_kikPendingUploads(files_found, report_folder, seeker, wrap_text, timezone_offset):
    data_list = []
    appID = ''
    contentID = ''
    progress = ''
    retriesRemaining = ''
    state = ''
    uploadStartTime = ''
    thumb = ''
    
    for file_found in files_found:
        file_found = str(file_found)
        
        if not file_found.endswith('pending_uploads'):
            continue
            
        tree = ET.parse(file_found)
        root = tree.getroot()
        a_dict = {}
        counter = 0
        for elem in root:
            for subelem in elem:
                for subelem2 in subelem:

                    if counter == 0:
                        key = subelem2.text
                        a_dict[key] = ''
                        counter += 1
                    else:
                        value = subelem2.text
                        a_dict[key] = value
                        counter = 0
                        
                appID = a_dict['appID']
                contentID = a_dict['contentID']
                progress = a_dict['progress']
                retriesRemaining = a_dict['retriesRemaining']
                state = a_dict['state']
                uploadStartTime = a_dict['uploadStartTime']
        
        pending_media_file = _find_pending_media_file(files_found, contentID)
        copied_name = _copy_pending_media_file(pending_media_file, report_folder) if pending_media_file else ''
        thumb = _build_pending_file_thumb(copied_name)
        
        data_list.append((uploadStartTime, appID, contentID, progress, retriesRemaining, state, thumb))

        a_dict = {}
                        
        if len(data_list) > 0:
            head_tail = os.path.split(file_found)
            description = 'Metadata from Kik media directory. Source are bplist files.'
            report = ArtifactHtmlReport('Kik Pending Uploads')
            report.start_artifact_report(report_folder, 'Kik Pending Uploads', description)
            report.add_script()
            data_headers = ('Upload Start Time','App ID','Content ID','Progress','Retries Remaining','State','Pending File')
            report.write_artifact_data_table(data_headers, data_list, head_tail[0],html_no_escape=['Pending File'])
            report.end_artifact_report()
            
            tsvname = 'Kik Pending Uploads'
            tsv(report_folder, data_headers, data_list, tsvname)
        else:
            logfunc('No data on Kik Pending Uploads')

__artifacts__ = {
    "kikPendingUploads": (
        "Kik",
        ('*/mobile/Containers/Shared/AppGroup/*/cores/private/*/chunked_upload_storage/pending_uploads','*/mobile/Containers/Shared/AppGroup/*/cores/private/*/chunked_upload_storage/data_cache/*'),
        get_kikPendingUploads)
}
