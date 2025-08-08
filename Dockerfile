#Imagen base
FROM python:3.12-slim

#Variable de entorno
ENV DEBIAN_FRONTEND=noninteractive

#Instalacion de proramas y dependencias
RUN apt update && apt install -y git

#Directorio de trabajo
WORKDIR /app

#Clona la herramienta desde github
RUN git clone https://github.com/0d1n-oss/caronte.git

#Instalar dependencias de el programa
RUN pip install --no-cache-dir -r requirements.txt

#Despliegue de el programa
CMD ["python3","main.py"]
