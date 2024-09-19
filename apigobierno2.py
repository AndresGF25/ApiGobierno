from google.cloud import api_keys_v2
from google.cloud import webrisk_v1
import requests
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, request, jsonify
import os
from pymongo import MongoClient
from pymongo.server_api import ServerApi

app = Flask(__name__)

# Configura la conexión a MongoDB
uri = "mongodb+srv://andresgordofon10:Planszombi152@cluster0.kgeia.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
cliente = MongoClient(uri, server_api=ServerApi('1'))

# Verifica la conexión a MongoDB
try:
    cliente.admin.command('ping')
    print("Ping exitoso. ¡Conexión exitosa a MongoDB!")
except Exception as e:
    print(f"Error de conexión: {e}")
    exit(1)

# Crear base de datos y colección en MongoDB
bd = cliente['Correos']
coleccion = bd['Phishing']

def create_api_key(project_id: str, suffix: str) -> str:
    """Crea una clave API para el proyecto especificado y devuelve la clave como cadena."""
    try:
        client = api_keys_v2.ApiKeysClient()
        key = api_keys_v2.Key()
        key.display_name = f"My first API key - {suffix}"

        request = api_keys_v2.CreateKeyRequest()
        request.parent = f"projects/{project_id}/locations/global"
        request.key = key

        response = client.create_key(request=request).result()
        api_key_string = response.key_string
        print(f"API Key creada: {api_key_string}")
        return api_key_string
    except Exception as e:
        print(f"Error creando la API Key: {e}")
        return None

def send_api_key_to_another_project(api_key_string: str, target_url: str):
    """Envía la clave API a otro proyecto mediante una solicitud POST."""
    data = {"api_key": api_key_string}
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(target_url, json=data, headers=headers)
        response.raise_for_status()
        print(f"API Key enviada exitosamente a {target_url}")
    except requests.exceptions.HTTPError as http_err:
        print(f"Error HTTP al enviar la API Key: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Error al enviar la API Key: {req_err}")
    except Exception as e:
        print(f"Error inesperado: {e}")

def recolectar_datos():
    """Recolecta datos de correos electrónicos de una API pública y verifica cada uno."""
    url = 'https://www.datos.gov.co/resource/jtnk-dmga.json'
    respuesta = requests.get(url)
    
    if respuesta.status_code == 200:
        try:
            datos_json = respuesta.json()
            correos = [dato['email_address'] for dato in datos_json[:50]]  # Extrae los primeros 50 correos
            
            for correo in correos:
                github_url = buscar_usuario_github(correo)
                is_phishing_email = check_email_phishing(correo)
                guardar_datos_en_mongodb(correo, github_url, is_phishing_email)
                
        except json.JSONDecodeError:
            print("Error al decodificar el JSON. El contenido no es un JSON válido.")
            print("Contenido de la respuesta:", respuesta.text)
    else:
        print(f"Error al hacer la solicitud: {respuesta.status_code}")

def buscar_usuario_github(correo):
    """Busca un usuario en GitHub basado en el nombre de usuario extraído del correo electrónico."""
    nombre_usuario = correo.split('@')[0]
    url = 'https://api.github.com/search/users'
    parametros = {'q': f'{nombre_usuario} in:login'}
    headers = {'Accept': 'application/vnd.github.v3+json'}

    try:
        respuesta = requests.get(url, headers=headers, params=parametros)
        respuesta.raise_for_status()
        resultado = respuesta.json()
        usuarios = resultado.get('items', [])
        if usuarios:
            return usuarios[0].get('html_url', '')
    except requests.exceptions.RequestException as e:
        print(f"Error al buscar el usuario en GitHub: {e}")

    return None

def check_email_phishing(email: str) -> bool:
    """Verifica si el dominio del correo electrónico está en la lista de amenazas de phishing."""
    client = webrisk_v1.WebRiskServiceClient()

    domain = email.split('@')[-1]
    try:
        response = client.search_uris(
            webrisk_v1.SearchUrisRequest(
                uri=f"http://{domain}",
                threat_types=[webrisk_v1.ThreatType.SOCIAL_ENGINEERING]
            )
        )

        if response.threat and response.threat.threat_types:
            print(f"El dominio {domain} del correo electrónico {email} es un riesgo de phishing.")
            return True
        else:
            print(f"El dominio {domain} del correo electrónico {email} parece seguro.")
            return False

    except Exception as e:
        print(f"Error al verificar el correo electrónico: {e}")
        return False

def guardar_datos_en_mongodb(correo, github_url, is_phishing_email):
    """Guarda la información del correo electrónico en la colección de MongoDB."""
    try:
        coleccion.insert_one({
            "correo": correo,
            "github_url": github_url,
            "is_phishing_email": is_phishing_email
        })
        print("Datos del correo guardados en MongoDB.")
    except Exception as e:
        print(f"Error al guardar datos en MongoDB: {e}")

def send_email(sender_email: str, sender_password: str, recipient_email: str, subject: str, content: str):
    """Envía un correo electrónico utilizando SMTP con autenticación en Gmail."""
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    msg.attach(MIMEText(content, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print(f"Email enviado exitosamente a {recipient_email}")
        return True
    except smtplib.SMTPException as e:
        print(f"Error enviando el correo: {e}")
        return False

def check_phishing(url: str) -> bool:
    """Verifica si la URL es un riesgo de phishing usando WebRisk."""
    client = webrisk_v1.WebRiskServiceClient()

    try:
        response = client.search_uris(
            webrisk_v1.SearchUrisRequest(
                uri=url,
                threat_types=[webrisk_v1.ThreatType.SOCIAL_ENGINEERING]
            )
        )

        if response.threat and response.threat.threat_types:
            print(f"La URL {url} es un riesgo de phishing: {response.threat.threat_types}")
            return True
        else:
            print(f"La URL {url} parece segura.")
            return False

    except Exception as e:
        print(f"Error al verificar la URL: {e}")
        return False

# Función principal que ejecuta el flujo principal del script
if __name__ == "__main__":
    project_id = "plucky-furnace-349821"
    suffix = "tu-sufijo-unico"
    api_key_string = create_api_key(project_id, suffix)

    if api_key_string:
        target_url = 'http://127.0.0.1:5001/receive-api-key'
        send_api_key_to_another_project(api_key_string, target_url)

    url_to_check = "https://szlhxd.com/Serve"
    is_phishing_url = check_phishing(url_to_check)
    check_email_phishing("tifel31717@marchub.com")
    recolectar_datos()
    datos = coleccion.find()
    for doc in datos:
        print(doc)
    check_email_phishing("tifel31717@marchub.com")
