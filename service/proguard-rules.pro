# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Main entry point (Java)
-keepclasseswithmembers class io.github.a13e300.tricky_store.Main {
    public static void main(java.lang.String[]);
}

# Remove debug logging in release builds
-assumenosideeffects class io.github.a13e300.tricky_store.Logger {
    public static void d(...);
    public static void dd(...);
}

# BouncyCastle - only keep what we actually use
-keep class org.bouncycastle.jcajce.provider.asymmetric.ec.** { *; }
-keep class org.bouncycastle.jcajce.provider.asymmetric.rsa.** { *; }
-keep class org.bouncycastle.jcajce.provider.asymmetric.x509.** { *; }
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }
-keep class org.bouncycastle.asn1.** { *; }
-keep class org.bouncycastle.cert.** { *; }
-keep class org.bouncycastle.operator.** { *; }
-dontwarn javax.naming.**

# Android/System classes
-keep class android.** { *; }
-keep class com.android.** { *; }
-keep class top.qwq2333.ohmykeymint.** { *; }

# Binder transaction codes
-keepclassmembers class * {
    static final int TRANSACTION_*;
}

-repackageclasses
-allowaccessmodification
-overloadaggressively
-keepattributes SourceFile,LineNumberTable,LocalVariableTable
-renamesourcefileattribute
-obfuscationdictionary          proguard-dic.txt
-classobfuscationdictionary     proguard-dic.txt
-packageobfuscationdictionary   proguard-dic.txt
