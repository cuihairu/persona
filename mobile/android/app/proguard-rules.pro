# JNI 入口按符号反射调用，混淆会改名导致 UnsatifiedLinkError——整类豁免
-keep class com.persona.mobile.PersonaBridge { *; }
