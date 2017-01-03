SVR_KEY=`cat svrkey.txt`; export SVR_KEY

java -jar target/skis.war --server.port=9080 -db=./ski.sqlite


