#!/bin/sh

cp=$CLASSPATH:
for x in `find /Users/sachinahuja/moofwd_workspace/Moofwd-Auth/lib -name *.jar` 
do cp+=$x:
done
cp+=/Users/tap/paas/fwdpaas/conf/log4j.properties:.

if [ $# -gt 0 ]
	then
	if [ $1 == "compile" ] 
		then
		rm -Rf build
		mkdir build

		cd src
		javac -cp $cp -d ../build org/json/*.java
		javac -cp $cp -d ../build moofwd/auth/*.java
		javac -cp $cp -d ../build moofwd/test/*.java
		cd ..
	fi
fi


cd build
java -cp $cp moofwd.test.Test

