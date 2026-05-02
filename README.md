# 🛡️ Lab 11 : Bypass de la Détection de Root Android
**Cible :** UnCrackable-Level1.apk (`owasp.mstg.uncrackable1`)  
**Auteur :** AMSOU ISMAIL 

---

## 📝 1. Présentation du Lab
L'objectif de ce laboratoire est de neutraliser les mécanismes de sécurité d'une application Android qui refuse de s'exécuter sur un appareil rooté[cite: 1]. Nous utilisons **Frida**, un outil d'instrumentation dynamique, pour modifier le comportement de l'application en mémoire sans altérer son code binaire[cite: 1].



---

## ⚙️ 2. Environnement de Test
*   **Appareil :** Émulateur Android (architecture x86).
*   **Système d'exploitation :** Windows 11.
*   **Outils :** 
    *   `frida` & `frida-tools` (version 17.5.1).
    *   `adb` (Android Debug Bridge).
    *   Scripts JS personnalisés : `bypass_root.js`, `bypass_native.js`.

---

## 🛠️ 3. Méthodologie et Commandes

### Étape 1 : Préparation du Serveur
Avant toute injection, le `frida-server` doit être opérationnel sur l'appareil cible[cite: 1].
```cmd
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
```

### Étape 2 : Identification du Processus
Nous listons les applications installées pour obtenir l'identifiant exact du package[cite: 1].
```cmd
frida-ps -Uai | findstr uncrackable
:: Résultat : owasp.mstg.uncrackable1
```

### Étape 3 : Injection Dynamique
L'attaque est lancée en forçant le démarrage de l'application avec nos scripts de hook[cite: 1].
```cmd
frida -U -f owasp.mstg.uncrackable1 -l lab11_sec\bypass_root.js -l lab11_sec\bypass_native.js
```

---

## 🔍 4. Analyse des Protections Contournées

L'application `UnCrackable-Level1` utilise trois types de vérifications Java[cite: 1] :

1.  **Vérification des Build Tags** : Elle cherche la chaîne `test-keys` qui indique une ROM personnalisée[cite: 1].
    *   *Solution* : Hook de `android.os.Build.TAGS` pour renvoyer `release-keys`[cite: 1].
2.  **Vérification des Fichiers Su** : Elle teste l'existence de fichiers comme `/system/xbin/su`[cite: 1].
    *   *Solution* : Hook de `java.io.File.exists()` pour renvoyer `false` sur ces chemins[cite: 1].
3.  **Vérification de l'exécution (Runtime)** : Elle tente d'exécuter la commande `su`[cite: 1].
    *   *Solution* : Hook de `Runtime.exec()` pour bloquer la commande[cite: 1].

---

## 📈 5. Résultats et Preuves (Captures d'écran)

### ❌ Avant l'attaque
L'application détecte le root et affiche une alerte bloquante : **"Root detected! This is unacceptable."** <img width="290" height="641" alt="image" src="https://github.com/user-attachments/assets/3dded897-8896-422e-9302-e2715e6fc43c" />
[cite: 1].

### ✅ Après l'attaque
L'application s'ouvre normalement sur le champ de saisie du "Secret String" sans aucune alerte <img width="299" height="631" alt="image" src="https://github.com/user-attachments/assets/1b9712d9-5734-4618-8a35-ad891a656305" />
[cite: 1].

### 💻 Logs de la Console Frida
Les logs confirment l'interception réussie des appels système :
*   `[+] Hook Build.TAGS -> release-keys`[cite: 1]
*   `[+] File.exists bypass for /system/xbin/su`[cite: 1]
*   `[+] Java layer bypass installed`[cite: 1]

---

## 💡 6. Conclusion
Ce lab démontre que les protections côté client (comme la détection de root) peuvent être contournées par un attaquant disposant de privilèges suffisants sur l'appareil[cite: 1]. L'utilisation de Frida permet une analyse granulaire et efficace des couches de sécurité Java et natives d'Android[cite: 1].
