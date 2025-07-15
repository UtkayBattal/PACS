#!/usr/bin/env python3

def check_packages():
    required_packages = [
        'sqlalchemy',
        'flask_sqlalchemy',
        'flask',
        'flask_login',
        'psycopg2',
        'zk',
        'pandas',
        'xlsxwriter',
        'pdfkit'
    ]
    
    missing_packages = []
    package_names = {
        'zk': 'pyzk'
    }
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package} başarıyla yüklendi")
        except ImportError as e:
            pip_package = package_names.get(package, package)
            missing_packages.append(pip_package)
            print(f"✗ {package} yüklenemedi: {str(e)}")
    
    if missing_packages:
        print("\nEksik paketler:")
        for package in missing_packages:
            print(f"- {package}")
        print("\nLütfen eksik paketleri yükleyin:")
        print("pip install " + " ".join(missing_packages))
        exit(1)
    else:
        print("\nTüm paketler başarıyla yüklendi!")

if __name__ == "__main__":
    check_packages() 