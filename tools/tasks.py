from invoke import Collection, run, task

import os, os.path
import subprocess
import json
import pprint

# ==============================================================================

_le_archive_filename_templates = {'certificate': 'cert%d.pem',
                                  'chain': 'chain%d.pem',
                                  'fullchain': 'fullchain%d.pem',
                                  'private_key': 'privkey%d.pem', 
                                  }


@task(help={'archive_path': "Path to letsencrypt archive files.",
            'server_url_root': "URL of server to post to, do not include `.well-known`",
            })
def import_letsencrypt_certs_archive(archive_path, server_url_root):
    """imports the archive path
    HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC
    
    usage:
        invoke import_letsencrypt_certs_archive --archive-path="/path/to" --server-url-root="http://0.0.0.0:6543"
        invoke import_letsencrypt_certs_archive --archive-path="/Users/jvanasco/webserver/tests/letsencrypt.test/credentials/letsencrypt_issueds" --server-url-root="http://0.0.0.0:6543"
    """
    if not archive_path:
        raise ValueError("missing `archive-path`")
    
    if server_url_root[:4] != 'http':
        raise ValueError("`server_url_root` does not look like a url")
    if '.well-known' in server_url_root:
        raise ValueError("do not include `.well-known`")
    
    if not os.path.isdir(archive_path):
        raise ValueError("`%s` is not a directory" % archive_path)

    # grab all the directories        
    dirs = [i for i in os.listdir(archive_path) if i[0] != '.']

    # empty queue
    filesets = []

    for d in dirs:
        dpath = os.path.join(archive_path, d)
        if not os.path.isdir(dpath):
            raise ValueError("`%s` is not a directory" % dpath)
        dfiles = [f for f in os.listdir(dpath) if f[0] != '.']
        # ensure we have the right files in here...
        if not dfiles:
            # no files, GREAT!
            continue
        # we best only have sets of 4 files...
        if len(dfiles) % 4:
            raise ValueError("`%s` does not look to be a letsencrypt directory" % dpath)
        total_sets = len(dfiles) / 4
        for i in range(1, total_sets + 1):
            fset = {}
            for (ftype, ftemplate) in _le_archive_filename_templates.items():
                fpath = os.path.join(dpath, ftemplate%i)
                if not os.path.exists(fpath):
                    raise ValueError("`%s` does not look to be a letsencrypt directory; expected %s" % (dpath, fpath))
                fset[ftype] = fpath
            filesets.append(fset)

    if not filesets:
        raise ValueError("No files!")
    
    server_url_root = server_url_root + ('' if server_url_root[-1] == '/' else '/')
    url = '%s.well-known/admin/certificate/upload/json' % server_url_root
    
    for fset in filesets:
        proc = subprocess.Popen(['curl',
                                 "--form", "private_key_file=@%s" % fset['private_key'],
                                 "--form", "certificate_file=@%s" % fset['certificate'],
                                 "--form", "chain_file=@%s" % fset['chain'],
                                 url
                                 ],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        json_response, err = proc.communicate()
        try:
            if not json_response:
                raise ValueError("error")
            json_response = json.loads(json_response)
            if ('result' not in json_response) or (json_response['result'] != 'success'):
                pprint.pprint(json_response)
                raise ValueError("error!")
            else:
                print "success | %s" % json_response
        except:
            raise
    return




namespace = Collection(import_letsencrypt_certs_archive, )
