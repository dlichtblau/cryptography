from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from lxml import etree
from signxml import XMLSigner, XMLVerifier
import xml.etree.cElementTree as ET
import binascii, datetime, pytz, hashlib
from dicttoxml import dicttoxml
import xml.etree.ElementTree as ET
import lxml.etree as ETE
from xml.dom import minidom

'''
Code to receive a simple string from the user and generate an XML message with the following components:
    i)      The user's input stored as a ciphertext-string (i.e. encrypted using a Private-Key)
    ii)     A timestamp showing the current time (i.e. generated upon receiving the user's input)
    iii)    The Publick-Key Information
    iv)     A digital signature of the XML message (i.e. generated prior to adding the signature to the XML message)
'''


######################################################################################
''' Class object to instantiate the XML Message '''
class XML_File:
    def __init__(self):
        self.ciphertext = binascii.hexlify(encrypted)
        self.timestamp = timestamp_x
        self.publicKeyInfo= pubKey_ascii
        self.signature = "DIGITAL SIGNATURE"# Temporary placeholder for digital signature (i.e. see generate_signature() function)

''' User Inputs the String '''
text_as_string = input("Enter a simple string to store in XML: ")

''' Timestamp Generator '''
timestamp_x = datetime.datetime.now(pytz.timezone('America/Toronto')).isoformat()
timestamp_y = datetime.datetime.now(pytz.timezone('America/Toronto')).isoformat()

######################################################################################
''' KEY GENERATOR '''
keyPair = RSA.generate(4096)

pubKey = keyPair.publickey()
pubkey_n={hex(pubKey.n)}
pubkey_e={hex(pubKey.e)}
pubkey_info = {"Public Key Nonce":pubkey_n, "Public Key E":pubkey_e}
#print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
pubKey_ascii = pubKeyPEM.decode('ascii')
#print(pubKeyPEM.decode('ascii'))

privkey_n={hex(pubKey.n)}
privkey_d={hex(keyPair.d)}
privkey_info = {"Private Key Nonce":privkey_n, "Private Key D":privkey_d}
#print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
privkey_ascii = privKeyPEM.decode('ascii')
#print(privKeyPEM.decode('ascii'))

text_as_bytes = text_as_string.encode()
encryptor = PKCS1_OAEP.new(keyPair)#pubKey)
#encryptor = PKCS1_OAEP.new(privkey_ascii)
encrypted = encryptor.encrypt(text_as_bytes)
encrypted_text_as_string = binascii.hexlify(encrypted)

decryptor = PKCS1_OAEP.new(keyPair)
decrypted = decryptor.decrypt(encrypted)
#print('Decrypted:', decrypted)

######################################################################################
'''
    Writing down the private and public keys to 'pem' files in the current working directory
'''
with open('public_pem.pem', 'wb') as pu:
    pu.write(pubKeyPEM)

with open('private_pem.pem', 'wb') as pr:
    pr.write(privKeyPEM)

######################################################################################
'''
GENERATE (I) DIGITAL-SIGNATURE      &&      (II) SIGNATURE-VERIFICATION

    Function to generate the signature:
                                        PARAMTERS:
                                                    - 'key'   :             - contents of Private/Public Key
                                                    - 'data'  :             - contents of the encrypted data (i.e. from file)
                                                    - 'signature_file' :    - file containing contents of the generated signature (i.e. the file containing the 'detatched'-SIGNATURE)

                                        What happens:
                                                    i)  Take the data   --> Read the data contents (i.e. read the data-file)
'''

def generate_signature(filename, data, signature_file):
    print("Generating signature for the XML file storing your string ...")
    '''
        INCREDIBLY DIRTY: I know and apologies :(
                                                    - dealing with character encodings is clearly an area which needs imrovement:
                                                                                                                                - Unicode vs Strings vs Bytes vs ASCII
                                                                                                                                - Encoding Unicode-Objects
                                                                                                                                    - encoding them before hashing
    '''
    # Opens the XML Message to read it and store it in the 'xml_bytes_read' buffer object which can then be hashed to generate an SHA256 Digital Signature of the message contents
    with open(filename, "rb") as xml_contents:
        xml_bytes_read = xml_contents.read()
        sha256_signature = hashlib.sha256(xml_bytes_read).hexdigest()
    
    # Stores the SHA256 Hash/Signature in a file (i.e. this is gratuitous and not necessary)
    with open(signature_file, 'wb') as f:#     Signature-Object is stored/written in a file (i.e. this will be the 'signature_file' object, as denoted {i.e. a binary file})
        signature = sha256_signature.encode('ascii')
        f.write(signature)

    return(signature)

def append_signature():
    original_tag_content = "DIGITAL SIGNATURE"
    filename = "meh2_xml.xml"
    sig_f = "digital_signature.txt"
    
    # Opens the XML Message to read it and store it in the 'xml_bytes_read' buffer object which can then be hashed to generate an SHA256 Digital Signature of the message contents
    with open(filename, "rb") as xml_contents:
            xml_bytes_read = xml_contents.read()
            sha256_signature = hashlib.sha256(xml_bytes_read).hexdigest()

    # Stores the SHA256 Hash/Signature in a file (i.e. this is gratuitous and not necessary)
    with open(sig_f, 'wb') as f:#     Signature-Object is stored/written in a file (i.e. this will be the 'sig_f' object, as denoted {i.e. a binary file})
        signature = sha256_signature.encode('ascii')
        f.write(signature)
    
    # Adding the encoding when the file is opened and written is needed to avoid a charmap error
    with open(filename, encoding="utf8") as f:
        tree = ETE.parse(f)
        root = tree.getroot()

        for elem in root.getiterator():
            try:
                elem.text = elem.text.replace(original_tag_content, str(signature))
            except AttributeError:
                pass

    # Adding the xml_declaration and method helped keep the header info at the top of the file.
    tree.write(filename, xml_declaration=True, method='xml', encoding="utf8")

######################################################################################

''' CREATE THE XML FILE '''
xml_file = vars(XML_File()) # converts XML_File to dictionary
xml = dicttoxml(xml_file, attr_type=False, custom_root='String') # set root node for the XML_File

# Generates the XML message/file and writes the requested contents to the file
with open("meh2_xml.xml", "wb") as file:
    file.write(xml)

######################################################################################
''' Just for aesthetics in the terminal '''
print()
print("---------------------------------------------------------------------------------------------------------------------")
print("Your Encrypted String Input: ", binascii.hexlify(encrypted))
print("---------------------------------------------------------------------------------------------------------------------")
print("Timestamp: ", timestamp_x)
print("---------------------------------------------------------------------------------------------------------------------")
print()
print("Public Key Information: ", pubKey_ascii)
print()
print("Private Key Information: ", privkey_ascii)
print()
print("---------------------------------------------------------------------------------------------------------------------")
print("Digital Signature (i.e. SHA256): ", generate_signature("meh2_xml.xml", pubKeyPEM, "digital_signature.txt"))
print("---------------------------------------------------------------------------------------------------------------------")
print()
print("The RSA-Generated Key-Pair:  ", keyPair)
print()
print("---------------------------------------------------------------------------------------------------------------------")
print()
print('Your original String (i.e. following decryption):   ', decrypted)
print()
print("---------------------------------------------------------------------------------------------------------------------")
print("---------------------------------------------------------------------------------------------------------------------")
append_signature()