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

```javascript
// bypass_root.js — Neutralise des checks Java courants (Build.TAGS, File.exists, Runtime.exec, RootBeer)

function safeContains(str, needle) {
  try { return (str || "").toLowerCase().indexOf((needle||"").toLowerCase()) !== -1; } catch (_) { return false; }
}

const suspiciousPaths = [
  "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
  "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
  "/system/bin/.ext/.su", "/system/usr/we-need-root/",
  "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
  "/system/bin/busybox", "/system/xbin/busybox"
];

Java.perform(function () {
  // 1) Forcer Build.TAGS à une valeur non suspecte
  try {
    const Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'TAGS', { get: function() { return 'release-keys'; } });
    console.log('[+] Hook Build.TAGS -> release-keys');
  } catch (e) { console.log('[-] Build.TAGS hook failed:', e); }

  // 2) RootBeer (si présent)
  try {
    const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function () { console.log('[+] RootBeer.isRooted -> false'); return false; };
    if (RootBeer.isRootedWithBusyBoxCheck) {
      RootBeer.isRootedWithBusyBoxCheck.implementation = function () { console.log('[+] RootBeer.isRootedWithBusyBoxCheck -> false'); return false; };
    }
  } catch (e) { console.log('[*] RootBeer non présent ou nom différent:', e.message); }

  // 3) File.exists -> retourner false pour chemins suspects
  try {
    const File = Java.use('java.io.File');
    File.exists.implementation = function () {
      const path = this.getAbsolutePath();
      if (suspiciousPaths.indexOf(path) !== -1) {
        console.log('[+] File.exists bypass for', path);
        return false;
      }
      return this.exists.call(this);
    };
  } catch (e) { console.log('[-] File.exists hook failed:', e); }

  // 4) Runtime.exec -> bloquer su/which/busybox
  try {
    const Runtime = Java.use('java.lang.Runtime');
    const JString = Java.use('java.lang.String');
    const StringArray = Java.use('[Ljava.lang.String;');

    function blockIfSuspicious(cmdOrArr) {
      const joined = Array.isArray(cmdOrArr) ? cmdOrArr.join(' ') : ('' + cmdOrArr);
      if (safeContains(joined, ' su') || joined.trim().toLowerCase().startsWith('su') || safeContains(joined, 'which su') || safeContains(joined, 'busybox')) {
        console.log('[+] Blocked Runtime.exec:', joined);
        return ['sh', '-c', 'echo'];
      }
      return null;
    }

    // exec(String)
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      const repl = blockIfSuspicious(cmd);
      return repl ? this.exec(JString.$new(repl.join(' '))) : this.exec(cmd);
    };
    // exec(String[])
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
      const js = arr ? Array.from(arr) : [];
      const repl = blockIfSuspicious(js);
      if (repl) {
        const a = StringArray.$new(repl.length);
        for (let i = 0; i < repl.length; i++) a[i] = JString.$new(repl[i]);
        return this.exec(a);
      }
      return this.exec(arr);
    };
    // exec(String, String[])
    Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (cmd, envp) {
      const repl = blockIfSuspicious(cmd);
      return repl ? this.exec(JString.$new(repl.join(' ')), envp) : this.exec(cmd, envp);
    };
    // exec(String[], String[])
    Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (arr, envp) {
      const js = arr ? Array.from(arr) : [];
      const repl = blockIfSuspicious(js);
      if (repl) {
        const a = StringArray.$new(repl.length);
        for (let i = 0; i < repl.length; i++) a[i] = JString.$new(repl[i]);
        return this.exec(a, envp);
      }
      return this.exec(arr, envp);
    };

    console.log('[+] Hooks Runtime.exec installés');
  } catch (e) { console.log('[-] Runtime.exec hooks failed:', e); }

  console.log('[+] Java layer bypass installed');
});
```

```javascript
// bypass_native.js — Neutralise open/openat/access/stat/lstat sur chemins suspects

const SUS = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/system/su',
  '/system/bin/busybox', '/system/xbin/busybox'
];

function isSuspiciousPath(ptrPath) {
  try { const p = ptrPath.readCString(); return !!p && (SUS.indexOf(p) !== -1 || p.indexOf('/proc/mounts') !== -1 || p.indexOf('/proc/self/mounts') !== -1); } catch (_) { return false; }
}

function hookFunc(name, argIndexForPath) {
  try {
    const addr = Module.getExportByName(null, name);
    Interceptor.attach(addr, {
      onEnter(args) {
        const pathPtr = argIndexForPath >= 0 ? args[argIndexForPath] : null;
        if (pathPtr && isSuspiciousPath(pathPtr)) {
          this.block = true;
          this.path = pathPtr.readCString();
        }
      },
      onLeave(retval) {
        if (this.block) {
          console.log('[+] Blocked', name, 'on', this.path);
          retval.replace(ptr(-1));
        }
      }
    });
    console.log('[+] Hooked', name);
  } catch (e) { /* silencieux si non dispo sur la plateforme */ }
}

hookFunc('open', 0);     // int open(const char *pathname, int flags, ...)
hookFunc('openat', 1);   // int openat(int dirfd, const char *pathname, int flags, ...)
hookFunc('access', 0);   // int access(const char *pathname, int mode)
hookFunc('stat', 0);     // int stat(const char *pathname, struct stat *buf)
hookFunc('lstat', 0);    // int lstat(const char *pathname, struct stat *buf)
```

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
<img width="696" height="61" alt="image" src="https://github.com/user-attachments/assets/4d6ad180-5f4a-4885-b6ff-f69ed2d515bb" />


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
