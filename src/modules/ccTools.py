from PyKCS11 import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from .certificateTools import load_certificate, verify_cert, check_certs
from cryptography.hazmat.primitives import hashes
import requests, datetime

lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

def getSlots():
    slots = pkcs11.getSlotList()
    slotsCC = []
    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            slotsCC.append(slot)
    return slotsCC

def getCards():
    slots = getSlots()
    cards = []
    for slot in slots:
        session = pkcs11.openSession(slot)
        phandle = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
        certificateDer = session.getAttributeValue(phandle, [CKA_VALUE])[0]
        cert = x509.load_der_x509_certificate(bytes(certificateDer), default_backend())
        for attr in cert.subject:
            if attr.oid._name == 'commonName':
                name = attr.value
            if attr.oid._name == 'serialNumber':
                BI = attr.value
        cards.append({'slot': slot, 'name': name, 'BI': BI[2:-1]})
        session.closeSession()
    return cards

def extractCert(certificate_label, slot):
    #Possible Labels:
    # AUTHENTICATION SUB CA
    # CITIZEN AUTHENTICATION CERTIFICATE
    # ROOT CA
    session = pkcs11.openSession(slot)
    certObject = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_LABEL, certificate_label)])[0]
    certificateDer = session.getAttributeValue(certObject, [CKA_VALUE])[0]
    cert = x509.load_der_x509_certificate(bytes(certificateDer), default_backend())
    session.closeSession()
    return cert

def verifyCertificateIntegrity(slot):
    citizenCert = extractCert('CITIZEN AUTHENTICATION CERTIFICATE', slot)
    subCert = extractCert('AUTHENTICATION SUB CA', slot)
    rootCert = extractCert('ROOT CA', slot)
    if(not check_certs(citizenCert, subCert)):
        return False
    if (not check_certs(subCert, rootCert)):
        return False
    return True

def verifyCertificateChain(slot):
    # First Step in Chain
    citizenCert = extractCert('CITIZEN AUTHENTICATION CERTIFICATE', slot)
    certSub = extractCert('AUTHENTICATION SUB CA', slot)
    if not check_certs(citizenCert, certSub):
        return False

    # Second Step in Chain
    rootCardCert = extractCert('ROOT CA', slot)
    if not check_certs(certSub, rootCardCert):
        return False

    # Exceptional Case if there is a autosigned certificate on card
    if rootCardCert.subject == rootCardCert.issuer:
        print('SELF SIGNED CERTIFICATE')
        for attr in citizenCert.issuer:
            if attr.oid._name == 'commonName':
                name = attr.value
                number1 = name[-4:]
        with open(os.path.join('..', os.path.join('certs', 'EC de Autenticacao do Cartao de Cidadao {}.cer'.format(number1))), 'rb') as file:
            certToCompare = load_certificate(file.read())
        if certToCompare.fingerprint(hashes.SHA256()) != certSub.fingerprint(hashes.SHA256()):
            return False
        for attr in certSub.issuer:
            if attr.oid._name == 'commonName':
                name = attr.value
                number2 = name[-3:]
        with open(os.path.join('..', os.path.join('certs', 'Cartao de Cidadao {}.cer'.format(number2))), 'rb') as file:
            rootCardCert = load_certificate(file.read())


    # Third Step in Chain
    with open(os.path.join('..', os.path.join('certs', 'ECRaizEstado-Multicert.cer')), 'rb') as file:
        rootStateCert = load_certificate(file.read())
    if not check_certs(rootCardCert, rootStateCert):
        return False

    # Fourth Step in Chain
    r = requests.get('https://pkiroot.multicert.com/cert/MCRootCA.cer')
    rootCert = load_certificate(r.content)
    if not check_certs(rootStateCert, rootCert):
        return False

    return True

def sign_data_CC(slot, data):
    session = pkcs11.openSession(slot)
    privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),
                                   (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
    signature = bytes(session.sign(privKey, data, Mechanism(CKM_SHA256_RSA_PKCS)))
    session.closeSession()
    return signature

def sign_data_CC_certificate(slot, data):
    signature = sign_data_CC(slot, data)
    cert = extractCert('CITIZEN AUTHENTICATION CERTIFICATE', slot)
    certPEM = cert.public_bytes(Encoding.PEM)
    return signature, certPEM

if __name__ == '__main__':
    print('Write code to test module')






