#!/usr/bin/env python3

import os
import shutil
import xml.etree.ElementTree as ET

from scripts.artifact_report import ArtifactHtmlReport
from scripts.html_security import escape_attr, sanitize_url
from scripts.ilapfuncs import logfunc, tsv


def _build_pending_file_thumb(report_folder, content_id):
    content_basename = os.path.basename(str(content_id) if content_id else '')
    if not content_basename:
        return ''

    if sanitize_url(content_basename) == '#':
        safe_src = '#'
    else:
        safe_src = sanitize_url(os.path.join(report_folder, content_basename))

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
        
        thumb = _build_pending_file_thumb(report_folder, contentID)
        
        data_list.append((uploadStartTime, appID, contentID, progress, retriesRemaining, state, thumb))

        a_dict = {}
                        
        if len(data_list) > 0:
            
            content_basename = os.path.basename(contentID) if contentID else ''
            for match in files_found:
                if content_basename and os.path.basename(match) == content_basename:
                    shutil.copy2(match, report_folder)
            
            # for x in len(data_list):
                # for match in files_found:
                    # if contentID in match:
                        # shutil.copy2(match, report_folder)
                        # data_file_name = os.path.basename(match)
                        # thumb = f'<img src="{report_folder}{data_file_name}"  width="300"></img>'
        
            # data_list.append((uploadStartTime, appID, contentID, progress, retriesRemaining, state, thumb))
        
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
