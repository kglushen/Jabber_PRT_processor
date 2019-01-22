import subprocess, os, platform, re, time
from zipfile import ZipFile
from dataclasses import dataclass
from typing import Iterator


@dataclass
class ProblemReport:
    prt_folder_path: str
    prt: str
    private_key: str

    @classmethod
    def define_prt(cls, prt_folder_path: str) -> Iterator:
        for file in os.listdir(prt_folder_path):
            if os.path.isfile(os.path.join(prt_folder_path, file)):
                if file[-3:] == 'enc':
                    yield cls(prt_folder_path, file, os.path.join(prt_folder_path, 'private_key.pem'))
                elif file[-3:] == 'zip':
                    yield cls(prt_folder_path, file, '')

    def decrypt_prt(self, executer_file, key_pass):
        enc_key = self.prt[:-2] + 'sk'
        output_file_name = self.prt[:-4]
        decrypt_command = '"{}" --privatekey "{}" --pass "{}"  --encryptionkey "{}" --encryptedfile "{}" --outputfile "{}" --mobile'.format(
            executer_file, self.private_key, key_pass, enc_key, self.prt, output_file_name)

        subprocess.run(decrypt_command)
        if os.path.isfile(os.path.join(self.prt_folder_path, output_file_name)):
            os.rename(os.path.join(self.prt_folder_path, self.prt),
                      os.path.join(self.prt_folder_path, 'decrypted', self.prt))
            os.rename(os.path.join(self.prt_folder_path, enc_key),
                      os.path.join(self.prt_folder_path, 'decrypted', enc_key))
            return output_file_name
        else:
            raise Exception('Unable to decrypt archive')

    def get_login_from_metadata(self, metadata: str):
        for line in metadata.read().decode('utf-16').splitlines():
            try:
                login = line.split(',')[-1]
                final_name = login + '_' + str(time.time()) + '.zip'
                return final_name
            except UnicodeDecodeError:
                print('Unable to find username in metadata file. Please check', self.prt)
                return None

    @staticmethod
    def get_login_from_allconfig(ptr_zip):
        for file_name in ptr_zip.namelist():
            if 'jabberAllConfig' in file_name:
                with ptr_zip.open(file_name, 'r') as all_config:
                    for line in all_config:
                        if 'suggestedusername' in line.decode('utf-8').lower():
                            try:
                                login = re.search(re.compile('suggestedusername>(.*)<'),
                                                  line.decode('utf-8').lower()).group(1)
                                final_name = login + '_' + str(time.time()) + '.zip'
                                return final_name
                            except AttributeError:
                                print('Unable to find username in jabberAllConfig.xml file. Please check')
                                return None

    def rename_prt(self) -> None:
        with ZipFile(os.path.join(self.prt_folder_path, self.prt)) as ptr_zip:
            try:
                with ptr_zip.open('metadata.txt') as metadata:
                    final_name = self.get_login_from_metadata(metadata)
            except KeyError:
                final_name = self.get_login_from_allconfig(ptr_zip)

        if final_name:
            os.rename(os.path.join(self.prt_folder_path, self.prt),
                      os.path.join(self.prt_folder_path, 'processed', final_name))
        else:
            print('SOMETHING WENT WRONG')

    def process_prt(self, executer_file: str, key_pass: str):

        if self.private_key:
            self.prt = self.decrypt_prt(executer_file, key_pass)

        self.rename_prt()


def main():
    os_name = platform.system()
    prt_folder_path = os.path.dirname(os.path.realpath(__file__))

    if os_name == 'Windows':
        executer_file = 'C:\Program Files (x86)\Cisco Systems\Cisco Jabber\CiscoJabberPrtDecrypter.exe'
        if not os.path.isfile(executer_file):
            Exception(
                'C:\Program Files (x86)\Cisco Systems\Cisco Jabber\CiscoJabberPrtDecrypter.exe is not found, please install')
    else:
        raise Exception('Check for compatible OS')

    for input_prt in ProblemReport.define_prt(prt_folder_path):
        input_prt.process_prt(executer_file, '12345')


if __name__ == '__main__':
    main()
