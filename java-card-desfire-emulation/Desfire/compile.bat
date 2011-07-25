set JAVA_SOURCE_ROOT=.\src

rem following call to javac must be on one line !
%JAVA_HOME%\bin\javac -g -source 1.3 -target 1.1 -classpath %JC_HOME%\lib\api.jar %JAVA_SOURCE_ROOT%com\gieseckedevrient\javacard\hellosmartcard\*.java

