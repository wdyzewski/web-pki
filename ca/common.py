from cryptography import x509

def is_valid_csr(input : str) -> bool:
    try:
        x509.load_pem_x509_csr(input.encode())
        return True
    except ValueError:
        return False