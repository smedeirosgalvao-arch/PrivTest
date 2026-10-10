# Site de perfil com painel /admin

## Rodar localmente
    npm install
    ADMIN_EMAIL=voce@exemplo.com ADMIN_PASSWORD='uma-senha-longa-12+' npm start
Site: http://localhost:3000 · Painel: http://localhost:3000/admin
E-mail e senha só são lidos no primeiro início (ficam como hash scrypt em data/site.db). Depois pode remover as variáveis.

## Publicar (precisa de disco persistente)
Docker: `docker build -t site .` e `docker run -p 3000:3000 -v site-data:/data -e ADMIN_EMAIL=... -e ADMIN_PASSWORD=... site`
Fly.io / Railway / VPS: monte um volume em `/data` (DATA_DIR) e use HTTPS (Fly e Railway já dão; em VPS use Caddy).
Tudo que importa fica em DATA_DIR: `site.db` (banco) e `uploads/` (imagens e vídeos). Faça backup dessa pasta.

## Variáveis
DATA_DIR, PORT, MAX_UPLOAD_MB (padrão 300), TRUST_PROXY=1 atrás de proxy, NODE_ENV=production (cookie Secure).
