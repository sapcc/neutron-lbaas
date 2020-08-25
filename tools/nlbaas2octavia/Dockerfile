FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
# grab kubernetes-entrypoint
RUN curl -Lvko /usr/local/bin/kubernetes-entrypoint https://github.wdf.sap.corp/d062284/k8s-entrypoint-build/releases/download/6d8d33d/kubernetes-entrypoint && chmod +x /usr/local/bin/kubernetes-entrypoint

COPY . .

#CMD [ "python", "./nlbaas2octavia.py" ]
