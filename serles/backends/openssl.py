import subprocess
import os, subprocess
from datetime import datetime, timedelta, timezone
from os.path import exists, join

class Backend:
    def __init__(self, config):
        cfg = config['openssl']

        self.cacert = cfg['cacert']
        self.cakey = cfg['cakey']

        self.validity_period = {}

        for t in ('weeks', 'days', 'hours', 'minutes', 'seconds'):
            k = 'validity_' + t
            if k in cfg:
                self.validity_period[t] = int(cfg[k])

        if len(self.validity_period) == 0:
            self.validity_period['days'] = 90

        self.data_dir = cfg['dataDir'] if 'dataDir' in cfg else '/tmp/serles'
        self.db_dir = self.data_dir + '/db'

        if not exists(self.cakey):
            subprocess.run([
                "openssl", "genrsa",
                "-out", self.cakey,
                "4096",
            ], stderr = subprocess.DEVNULL)

        if not exists(self.cacert):
            subprocess.run([
                "openssl", "req",
                "-new", "-x509",
                "-nodes",
                "-days", "3650",
                "-subj", "/C=XX/O=Serles",
                "-key", self.cakey,
                "-out", self.cacert,
            ])

    def sign(self, csr, subjectDN, subjectAltNames, email):
        cf_filename = self._create_openssl_config(subjectAltNames)
        inform = 'pem' if (len(csr) > 0 and chr(csr[0]) == '-') else 'der'
        csr_filename = join(self.data_dir, 'csr.' + inform)
        cert_filename = join(self.data_dir, 'certificate.pem')

        with open(csr_filename, 'wb') as f:
            f.write(csr)

        ca_cert = self.cacert
        ca_key = self.cakey

        t = datetime.now(timezone.utc)
        startdate = t.strftime('%y%m%d%H%M%SZ')
        t += timedelta(**self.validity_period)
        enddate = t.strftime('%y%m%d%H%M%SZ')

        proc = subprocess.run([
            'openssl', 'ca', '-batch',
            '-config', cf_filename,
            '-extensions', 'v3_req',
            '-startdate', startdate,
            '-enddate', enddate,
            '-notext',
            '-out', cert_filename,
            '-cert', ca_cert,
            '-keyfile', ca_key,
            '-in', csr_filename,
            '-inform', inform
        ])

        chain = open(cert_filename, 'rb').read() + open(ca_cert, "rb").read()
        return chain.decode("utf-8"), None

    def _create_openssl_config(self, subjectAltNames):
        os.makedirs(self.data_dir, exist_ok = True)
        os.makedirs(self.db_dir, exist_ok = True)

        cf_filename = join(self.data_dir, 'openssl.conf')
        db_filename = join(self.db_dir, 'certs.db')

        # if no DB file exists, we need to create an empty one
        if not os.path.exists(db_filename):
            with open(db_filename, 'w') as f:
                pass

        with open(cf_filename, 'w') as f:
            f.write('[v3_req]\n')
            f.write('authorityKeyIdentifier=keyid,issuer\n')
            f.write('basicConstraints=CA:FALSE\n')
            f.write('keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n')
            f.write('subjectAltName = @alt_names\n')
            f.write('\n')
            f.write('[alt_names]\n')
            for i, s in enumerate(subjectAltNames):
                f.write('DNS.%d = %s\n' % (i + 1, s))
            f.write('\n')
            f.write('[ca]\n')
            f.write('default_ca = my_default_ca\n')
            f.write('\n')
            f.write('[my_default_ca]\n')
            f.write('new_certs_dir = %s\n' % (self.db_dir))
            f.write('database      = %s\n' % (db_filename))
            f.write('default_md    = default\n')
            f.write('rand_serial   = 1\n')
            f.write('policy        = my_ca_policy\n')
            f.write('copy_extensions = copy\n')
            f.write('email_in_dn   = no\n')
            f.write('default_days  = 365\n')
            f.write('\n')
            f.write('[my_ca_policy]\n')
            f.write('\n')

        return cf_filename
