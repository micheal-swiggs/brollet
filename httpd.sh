
if [[ $1 -eq "" ]]
then
  PORT=9696
else
  PORT=$1
fi

echo "web server running at http://localhost:$PORT"

#(cd web; python -u -m CGIHTTPServer $PORT)
(cd web; ../webServer $PORT)

