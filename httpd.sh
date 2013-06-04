echo "web server running at http://localhost:9696"

(cd web; python -u -m CGIHTTPServer 9696)
