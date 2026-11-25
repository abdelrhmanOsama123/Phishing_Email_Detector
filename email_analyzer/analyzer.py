"""Rule-based email safety checks and report text used by app.py."""
import re
import socket
import difflib
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlparse


# Offline language support for the email safety checker.
LANGUAGES = ("English", "Arabic", "Spanish", "French")

DETECTION_PHRASES = {
    "English": {
        "subject": (),
        "body": (),
        "credentials": (),
        "pretext": (),
        "finance": (),
        "browser": (),
        "lure": (),
        "attachment": ("attach", "attached", "attachment"),
    },
    "Arabic": {
        "subject": (
            "عاجل", "إجراء فوري", "مطلوب اتخاذ إجراء", "تم تعليق حسابك",
            "تحقق من حسابك", "نشاط غير معتاد", "تنبيه أمني", "فشل الدفع",
            "انتهت صلاحية", "تم إيقاف الحساب",
        ),
        "body": (
            "أكد هويتك", "تحقق من حسابك", "خلال 24 ساعة", "خلال 48 ساعة",
            "اضغط هنا", "اضغط على الرابط", "سيتم تعليق حسابك", "نشاط غير معتاد",
            "إعادة تعيين كلمة المرور", "تحديث معلومات الدفع", "تحويل بنكي",
            "بطاقة هدايا", "لقد فزت", "طالب عزيزي", "عميل عزيزي",
        ),
        "credentials": ("كلمة المرور", "رقم الضمان الاجتماعي", "بطاقة ائتمان", "رقم البطاقة", "رمز التحقق"),
        "pretext": ("متابعة مكالمتنا", "كما ناقشنا", "حسب محادثتنا", "كما اتفقنا", "كما وعدنا"),
        "finance": ("تحويل مالي", "فاتورة", "كشف حساب", "تحويل بنكي", "دفعة", "تفاصيل البنك",
                    "رقم الحساب", "أمر شراء", "رواتب", "الرصيد المستحق"),
        "browser": ("في المتصفح", "افتح في المتصفح", "عارض المستندات", "عارض الويب"),
        "lure": ("فاكس", "بريد صوتي", "مستند آمن", "مستند مشترك", "رسالة مشفرة"),
        "attachment": ("مرفق", "المرفقات"),
    },
    "Spanish": {
        "subject": (
            "urgente", "acción inmediata", "acción requerida", "cuenta suspendida",
            "verifica tu cuenta", "actividad inusual", "alerta de seguridad",
            "pago rechazado", "caduca", "cuenta bloqueada",
        ),
        "body": (
            "confirma tu identidad", "verifica tu cuenta", "en 24 horas", "en 48 horas",
            "haz clic aquí", "haz clic en el enlace", "se suspenderá la cuenta",
            "actividad inusual", "restablece tu contraseña", "actualiza tu pago",
            "transferencia bancaria", "tarjeta regalo", "has ganado", "estimado cliente",
        ),
        "credentials": ("contraseña", "número de seguridad social", "tarjeta de crédito",
                        "número de tarjeta", "código pin", "código de seguridad"),
        "pretext": ("dando seguimiento a nuestra llamada", "como hablamos", "según nuestra conversación",
                    "como acordamos", "como prometimos"),
        "finance": ("remesa", "factura", "extracto", "transferencia", "pago", "datos bancarios",
                    "número de cuenta", "orden de compra", "nómina", "saldo pendiente"),
        "browser": ("en tu navegador", "en un navegador", "abre en el navegador", "visor de documentos",
                    "visor web"),
        "lure": ("fax", "buzón de voz", "documento seguro", "documento compartido", "mensaje cifrado"),
        "attachment": ("adjunto", "archivo adjunto", "archivos adjuntos"),
    },
    "French": {
        "subject": (
            "urgent", "action immédiate", "action requise", "compte suspendu",
            "vérifiez votre compte", "activité inhabituelle", "alerte de sécurité",
            "paiement refusé", "expire", "compte bloqué",
        ),
        "body": (
            "confirmez votre identité", "vérifiez votre compte", "dans les 24 heures",
            "dans les 48 heures", "cliquez ici", "cliquez sur le lien",
            "votre compte sera suspendu", "activité inhabituelle", "réinitialisez votre mot de passe",
            "mettez à jour votre paiement", "virement bancaire", "carte cadeau",
            "vous avez gagné", "cher client",
        ),
        "credentials": ("mot de passe", "numéro de sécurité sociale", "carte de crédit",
                        "numéro de carte", "code pin", "cryptogramme"),
        "pretext": ("suite à notre appel", "comme discuté", "selon notre conversation",
                    "comme convenu", "comme promis"),
        "finance": ("virement", "facture", "relevé", "paiement", "coordonnées bancaires",
                    "numéro de compte", "bon de commande", "paie", "solde dû"),
        "browser": ("dans votre navigateur", "dans un navigateur", "ouvrez dans le navigateur",
                    "visionneuse de documents", "visionneuse web"),
        "lure": ("fax", "messagerie vocale", "document sécurisé", "document partagé", "message chiffré"),
        "attachment": ("pièce jointe", "pièces jointes", "fichier joint"),
    },
}

UI_TEXT = {
    "English": {
        "window_title": "Email Safety Check",
        "banner": "Tell us about the email",
        "language": "Analysis language:",
        "email_details": "Email details",
        "sender": "Sender (From):",
        "recipient": "Recipient (To):",
        "subject": "Subject Line:",
        "reply_to": "Reply-To (optional):",
        "attachments": "Attachments (optional):",
        "sender_placeholder": "Example: security@paypal-verify.com",
        "attachments_placeholder": "e.g. invoice.zip, document.svg",
        "address_details": "Address details (optional)",
        "sender_ip": "Sender IP:",
        "recipient_ip": "Recipient IP:",
        "message": "Email message",
        "check": "CHECK THIS EMAIL",
        "clear": "CLEAR INPUTS",
        "about_button": "ABOUT",
        "save": "SAVE REPORT",
        "results": "Your safety check",
        "ready": "Ready",
        "starting": "Starting the safety check...",
        "resolving": "Resolving IP addresses...",
        "status_sender": "Checking who sent it",
        "status_subject": "Looking at the subject",
        "status_thread": "Checking the conversation",
        "status_links": "Looking at the links",
        "status_ips": "Checking the sender addresses",
        "status_body": "Reading the message",
        "status_identity": "Matching names and domains",
        "status_complete": "Safety check complete",
        "language_changed": "Language changed. Run the check again.",
        "missing_input": "Missing input",
        "missing_sender": "Sender (From) is mandatory.",
        "missing_content": "Enter a subject line and/or email content.",
        "nothing_to_save": "Nothing to save yet",
        "check_first": "Check an email first, then save the result.",
        "saved": "Saved",
        "saved_to": "Report saved to:\n",
        "save_dialog_title": "Save report",
        "report_filetype": "Text report",
        "risk_score": "Risk score",
        "report_title": "EMAIL SAFETY CHECK",
        "from": "From",
        "to": "To",
        "reply_to_report": "Reply-To",
        "subject_report": "Subject",
        "attachments_report": "Attachments",
        "result": "RESULT",
        "no_value": "(none)",
        "none_listed": "(none listed)",
        "noticed": "WHAT WE NOTICED:",
        "no_findings": "  • We did not find any clear warning signs.\n",
        "next_step": "WHAT TO DO NEXT:",
        "thread_info": "ABOUT THE REPLY THREAD:",
        "ip_info": "ABOUT THE ADDRESS CHECK:",
        "links_checked": "LINKS CHECKED:",
        "disclaimer": (
            "This is an automated guide, not proof. When in doubt, contact the "
            "organization through a known official website or phone number."
        ),
        "evidence": "Evidence",
        "thread_reply": 'Reply/forward detected ("{subject}", {count} prefix(es)).',
        "thread_not_reply": "Not a reply (no Re:/Fw: prefix).",
        "thread_quoted": "Earlier messages quoted in the body: {quoted}. Newest message analyzed: {characters} characters.",
        "quoted_yes": "yes",
        "quoted_none": "none",
        "sender_ip_info": "Sender IP {ip}: {kind}",
        "recipient_ip_info": "Recipient IP {ip}: {kind}",
        "rdns_unavailable": "reverse DNS: unavailable (offline or timed out)",
        "rdns_none": "reverse DNS: none (no PTR record)",
        "rdns_found": "reverse DNS: {hostname}",
        "placeholder_result": "Paste an email above, then check it for warning signs.",
        "about_title": "About this check",
        "about_text": (
            "Email Safety Check\n\nIt looks for common warning signs, including:\n"
            " - sender or Reply-To addresses that do not match\n"
            " - urgent or unusual subject lines\n"
            " - shortened or deceptive links\n"
            " - familiar phishing phrases\n"
            " - risky or disguised attachments\n"
            " - brands or domains that appear mismatched\n\n"
            "This is a helpful guide, not proof that an email is safe or unsafe. "
            "If something feels wrong, verify it through a known official channel."
        ),
    },
    "Arabic": {
        "window_title": "فحص سلامة البريد الإلكتروني",
        "banner": "أدخل تفاصيل البريد الإلكتروني",
        "language": "لغة التحليل:",
        "email_details": "تفاصيل البريد الإلكتروني",
        "sender": "المرسل (من):",
        "recipient": "المستلم (إلى):",
        "subject": "موضوع الرسالة:",
        "reply_to": "الرد إلى (اختياري):",
        "attachments": "المرفقات (اختياري):",
        "sender_placeholder": "مثال: security@paypal-verify.com",
        "attachments_placeholder": "مثال: invoice.zip, document.svg",
        "address_details": "تفاصيل العناوين (اختياري)",
        "sender_ip": "عنوان IP للمرسل:",
        "recipient_ip": "عنوان IP للمستلم:",
        "message": "نص البريد الإلكتروني",
        "check": "فحص البريد",
        "clear": "مسح المدخلات",
        "about_button": "حول",
        "save": "حفظ التقرير",
        "results": "نتيجة فحص السلامة",
        "ready": "جاهز",
        "starting": "جارٍ بدء فحص السلامة...",
        "resolving": "جارٍ التحقق من عناوين IP...",
        "status_sender": "التحقق من هوية المرسل",
        "status_subject": "فحص موضوع الرسالة",
        "status_thread": "فحص سلسلة المحادثة",
        "status_links": "فحص الروابط",
        "status_ips": "فحص عناوين المرسل",
        "status_body": "قراءة نص الرسالة",
        "status_identity": "مطابقة الأسماء والنطاقات",
        "status_complete": "اكتمل فحص السلامة",
        "language_changed": "تم تغيير اللغة. أعد إجراء الفحص.",
        "missing_input": "مدخلات ناقصة",
        "missing_sender": "حقل المرسل (من) مطلوب.",
        "missing_content": "أدخل موضوع الرسالة أو محتواها.",
        "nothing_to_save": "لا يوجد تقرير للحفظ",
        "check_first": "افحص رسالة بريد إلكتروني أولاً، ثم احفظ النتيجة.",
        "saved": "تم الحفظ",
        "saved_to": "تم حفظ التقرير في:\n",
        "save_dialog_title": "حفظ التقرير",
        "report_filetype": "تقرير نصي",
        "risk_score": "درجة الخطورة",
        "report_title": "فحص سلامة البريد الإلكتروني",
        "from": "من",
        "to": "إلى",
        "reply_to_report": "الرد إلى",
        "subject_report": "الموضوع",
        "attachments_report": "المرفقات",
        "result": "النتيجة",
        "no_value": "(لا يوجد)",
        "none_listed": "(لم يتم إدراج أي مرفقات)",
        "noticed": "ما لاحظناه:",
        "no_findings": "  • لم نعثر على مؤشرات تحذير واضحة.\n",
        "next_step": "ما الخطوة التالية؟",
        "thread_info": "معلومات عن سلسلة الردود:",
        "ip_info": "معلومات عن فحص العناوين:",
        "links_checked": "الروابط التي تم فحصها:",
        "disclaimer": (
            "هذا الفحص إرشادي ولا يثبت سلامة الرسالة أو خطورتها. عند الشك، "
            "تواصل مع المؤسسة عبر موقع رسمي أو رقم هاتف معروف."
        ),
        "evidence": "الدليل",
        "thread_reply": 'تم اكتشاف رد أو إعادة توجيه ("{subject}"، {count} من البادئات).',
        "thread_not_reply": "ليست رسالة رد (لا توجد بادئة Re أو Fw).",
        "thread_quoted": "الرسائل السابقة المقتبسة في النص: {quoted}. عدد أحرف أحدث رسالة: {characters}.",
        "quoted_yes": "نعم",
        "quoted_none": "لا يوجد",
        "sender_ip_info": "عنوان IP للمرسل {ip}: {kind}",
        "recipient_ip_info": "عنوان IP للمستلم {ip}: {kind}",
        "rdns_unavailable": "DNS العكسي: غير متاح (انقطاع الاتصال أو انتهاء المهلة)",
        "rdns_none": "DNS العكسي: لا يوجد سجل PTR",
        "rdns_found": "DNS العكسي: {hostname}",
        "placeholder_result": "أدخل رسالة بريد إلكتروني أعلاه ثم افحصها بحثاً عن مؤشرات تحذير.",
        "about_title": "حول هذا الفحص",
        "about_text": (
            "فحص سلامة البريد الإلكتروني\n\nيبحث عن مؤشرات تحذير شائعة، منها:\n"
            " - عدم تطابق عنوان المرسل أو الرد مع المتوقع\n"
            " - عناوين رسائل عاجلة أو غير معتادة\n"
            " - روابط مختصرة أو مضللة\n"
            " - عبارات شائعة في رسائل التصيد\n"
            " - مرفقات خطرة أو مخفية النوع\n"
            " - عدم تطابق العلامات التجارية أو النطاقات\n\n"
            "هذا الفحص إرشادي وليس دليلاً قاطعاً على سلامة الرسالة أو خطورتها. "
            "عند الشك، تحقق عبر قناة رسمية معروفة."
        ),
    },
    "Spanish": {
        "window_title": "Comprobación de seguridad del correo",
        "banner": "Cuéntanos sobre el correo",
        "language": "Idioma del análisis:",
        "email_details": "Detalles del correo",
        "sender": "Remitente (De):",
        "recipient": "Destinatario (Para):",
        "subject": "Asunto:",
        "reply_to": "Responder a (opcional):",
        "attachments": "Archivos adjuntos (opcional):",
        "sender_placeholder": "Ejemplo: security@paypal-verify.com",
        "attachments_placeholder": "p. ej., invoice.zip, document.svg",
        "address_details": "Detalles de direcciones (opcional)",
        "sender_ip": "IP del remitente:",
        "recipient_ip": "IP del destinatario:",
        "message": "Mensaje de correo",
        "check": "ANALIZAR CORREO",
        "clear": "BORRAR DATOS",
        "about_button": "ACERCA DE",
        "save": "GUARDAR INFORME",
        "results": "Comprobación de seguridad",
        "ready": "Listo",
        "starting": "Iniciando la comprobación...",
        "resolving": "Consultando direcciones IP...",
        "status_sender": "Comprobando quién lo envió",
        "status_subject": "Revisando el asunto",
        "status_thread": "Comprobando la conversación",
        "status_links": "Revisando los enlaces",
        "status_ips": "Comprobando las direcciones del remitente",
        "status_body": "Leyendo el mensaje",
        "status_identity": "Comparando nombres y dominios",
        "status_complete": "Comprobación completada",
        "language_changed": "Cambió el idioma. Vuelve a analizar el correo.",
        "missing_input": "Faltan datos",
        "missing_sender": "El remitente (De) es obligatorio.",
        "missing_content": "Introduce un asunto o el contenido del correo.",
        "nothing_to_save": "No hay nada que guardar",
        "check_first": "Analiza un correo antes de guardar el resultado.",
        "saved": "Guardado",
        "saved_to": "Informe guardado en:\n",
        "save_dialog_title": "Guardar informe",
        "report_filetype": "Informe de texto",
        "risk_score": "Puntuación de riesgo",
        "report_title": "COMPROBACIÓN DE SEGURIDAD DEL CORREO",
        "from": "De",
        "to": "Para",
        "reply_to_report": "Responder a",
        "subject_report": "Asunto",
        "attachments_report": "Archivos adjuntos",
        "result": "RESULTADO",
        "no_value": "(ninguno)",
        "none_listed": "(ninguno indicado)",
        "noticed": "LO QUE DETECTAMOS:",
        "no_findings": "  • No encontramos señales de alerta claras.\n",
        "next_step": "QUÉ HACER AHORA:",
        "thread_info": "INFORMACIÓN DEL HILO:",
        "ip_info": "INFORMACIÓN DE DIRECCIONES:",
        "links_checked": "ENLACES COMPROBADOS:",
        "disclaimer": (
            "Esta guía automatizada no demuestra que un correo sea seguro o peligroso. "
            "En caso de duda, contacta con la organización mediante un sitio web oficial "
            "o un número de teléfono conocido."
        ),
        "evidence": "Evidencia",
        "thread_reply": 'Se detectó una respuesta o reenvío ("{subject}", {count} prefijo(s)).',
        "thread_not_reply": "No es una respuesta (sin prefijo Re:/Fw:).",
        "thread_quoted": "Mensajes anteriores citados: {quoted}. Caracteres del mensaje más reciente: {characters}.",
        "quoted_yes": "sí",
        "quoted_none": "ninguno",
        "sender_ip_info": "IP del remitente {ip}: {kind}",
        "recipient_ip_info": "IP del destinatario {ip}: {kind}",
        "rdns_unavailable": "DNS inverso: no disponible (sin conexión o tiempo agotado)",
        "rdns_none": "DNS inverso: sin registro PTR",
        "rdns_found": "DNS inverso: {hostname}",
        "placeholder_result": "Pega un correo arriba y comprueba si hay señales de alerta.",
        "about_title": "Acerca de esta comprobación",
        "about_text": (
            "Comprobación de seguridad del correo\n\nBusca señales de alerta comunes, como:\n"
            " - remitentes o respuestas que no coinciden\n"
            " - asuntos urgentes o inusuales\n"
            " - enlaces acortados o engañosos\n"
            " - frases frecuentes de phishing\n"
            " - adjuntos peligrosos o disfrazados\n"
            " - marcas o dominios que no coinciden\n\n"
            "Esta guía no demuestra que un correo sea seguro o peligroso. "
            "Si algo parece sospechoso, verifícalo por un canal oficial conocido."
        ),
    },
    "French": {
        "window_title": "Vérification de la sécurité des e-mails",
        "banner": "À propos de l’e-mail",
        "language": "Langue d’analyse :",
        "email_details": "Détails de l’e-mail",
        "sender": "Expéditeur (De) :",
        "recipient": "Destinataire (À) :",
        "subject": "Objet :",
        "reply_to": "Répondre à (facultatif) :",
        "attachments": "Pièces jointes (facultatif) :",
        "sender_placeholder": "Exemple : security@paypal-verify.com",
        "attachments_placeholder": "p. ex. invoice.zip, document.svg",
        "address_details": "Détails des adresses (facultatif)",
        "sender_ip": "IP de l’expéditeur :",
        "recipient_ip": "IP du destinataire :",
        "message": "Message de l’e-mail",
        "check": "ANALYSER L’E-MAIL",
        "clear": "EFFACER LES CHAMPS",
        "about_button": "À PROPOS",
        "save": "ENREGISTRER LE RAPPORT",
        "results": "Vérification de sécurité",
        "ready": "Prêt",
        "starting": "Démarrage de la vérification...",
        "resolving": "Vérification des adresses IP...",
        "status_sender": "Vérification de l’expéditeur",
        "status_subject": "Examen de l’objet",
        "status_thread": "Vérification de la conversation",
        "status_links": "Examen des liens",
        "status_ips": "Vérification des adresses de l’expéditeur",
        "status_body": "Lecture du message",
        "status_identity": "Comparaison des noms et des domaines",
        "status_complete": "Vérification terminée",
        "language_changed": "La langue a changé. Relancez l’analyse.",
        "missing_input": "Informations manquantes",
        "missing_sender": "L’expéditeur (De) est obligatoire.",
        "missing_content": "Saisissez un objet et/ou le contenu de l’e-mail.",
        "nothing_to_save": "Aucun résultat à enregistrer",
        "check_first": "Analysez d’abord un e-mail, puis enregistrez le résultat.",
        "saved": "Enregistré",
        "saved_to": "Rapport enregistré dans :\n",
        "save_dialog_title": "Enregistrer le rapport",
        "report_filetype": "Rapport texte",
        "risk_score": "Score de risque",
        "report_title": "VÉRIFICATION DE LA SÉCURITÉ DES E-MAILS",
        "from": "De",
        "to": "À",
        "reply_to_report": "Répondre à",
        "subject_report": "Objet",
        "attachments_report": "Pièces jointes",
        "result": "RÉSULTAT",
        "no_value": "(aucun)",
        "none_listed": "(aucune indiquée)",
        "noticed": "ÉLÉMENTS DÉTECTÉS :",
        "no_findings": "  • Aucun signe d’alerte clair n’a été détecté.\n",
        "next_step": "QUE FAIRE ENSUITE :",
        "thread_info": "À PROPOS DU FIL DE DISCUSSION :",
        "ip_info": "À PROPOS DE LA VÉRIFICATION DES ADRESSES :",
        "links_checked": "LIENS VÉRIFIÉS :",
        "disclaimer": (
            "Ce guide automatisé ne prouve pas qu’un e-mail est sûr ou dangereux. "
            "En cas de doute, contactez l’organisation via un site officiel ou un "
            "numéro de téléphone connu."
        ),
        "evidence": "Éléments observés",
        "thread_reply": 'Réponse ou transfert détecté (« {subject} », {count} préfixe(s)).',
        "thread_not_reply": "Ce n’est pas une réponse (aucun préfixe Re:/Fw:).",
        "thread_quoted": "Messages précédents cités : {quoted}. Caractères du message le plus récent : {characters}.",
        "quoted_yes": "oui",
        "quoted_none": "aucun",
        "sender_ip_info": "IP de l’expéditeur {ip} : {kind}",
        "recipient_ip_info": "IP du destinataire {ip} : {kind}",
        "rdns_unavailable": "DNS inverse : indisponible (hors ligne ou délai dépassé)",
        "rdns_none": "DNS inverse : aucun enregistrement PTR",
        "rdns_found": "DNS inverse : {hostname}",
        "placeholder_result": "Collez un e-mail ci-dessus pour rechercher des signes d’alerte.",
        "about_title": "À propos de cette vérification",
        "about_text": (
            "Vérification de la sécurité des e-mails\n\nElle recherche des signes d’alerte courants, notamment :\n"
            " - des adresses d’expéditeur ou de réponse incohérentes\n"
            " - des objets urgents ou inhabituels\n"
            " - des liens raccourcis ou trompeurs\n"
            " - des expressions courantes d’hameçonnage\n"
            " - des pièces jointes risquées ou déguisées\n"
            " - des marques ou domaines incohérents\n\n"
            "Ce guide ne prouve pas qu’un e-mail est sûr ou dangereux. "
            "En cas de doute, vérifiez par un canal officiel connu."
        ),
    },
}

LOCALIZED_FINDING_TITLES = {
    "Arabic": {
        "The sender is missing": "عنوان المرسل غير موجود",
        "The sender address looks incomplete": "عنوان المرسل غير مكتمل",
        "The sender address looks suspicious": "عنوان المرسل يبدو مريباً",
        "The domain may try to look familiar": "قد يحاول النطاق تقليد نطاق معروف",
        "The sender uses a commonly abused domain ending": "يستخدم المرسل نهاية نطاق شائعة في إساءة الاستخدام",
        "A personal email provider is posing as a business": "يبدو أن بريدًا شخصيًا ينتحل صفة شركة",
        "The sender domain is unusual": "نطاق المرسل غير معتاد",
        "The subject creates urgency": "موضوع الرسالة يخلق شعوراً بالإلحاح",
        "The subject uses lots of capital letters": "يستخدم الموضوع أحرفاً كبيرة بكثرة",
        "The subject uses unusual punctuation": "يستخدم الموضوع علامات ترقيم غير معتادة",
        "A link is hiding its real destination": "يخفي الرابط وجهته الحقيقية",
        "A link appears designed to hide its true address": "يبدو أن الرابط مصمم لإخفاء عنوانه الحقيقي",
        "A link may imitate a trusted website": "قد يقلد الرابط موقعاً موثوقاً",
        "A link imitates a familiar brand": "يقلد الرابط علامة تجارية معروفة",
        "The link uses a commonly abused domain ending": "يستخدم الرابط نهاية نطاق شائعة في إساءة الاستخدام",
        "The link does not use HTTPS": "لا يستخدم الرابط HTTPS",
        "The link has an unusually complex address": "عنوان الرابط معقد بشكل غير معتاد",
        "The link does not match the sender": "الرابط لا يتطابق مع المرسل",
        "The message uses familiar phishing language": "تستخدم الرسالة عبارات شائعة في التصيد",
        "The message asks for private information": "تطلب الرسالة معلومات خاصة",
        "The message claims to be from a brand but differs from the sender": "تدعي الرسالة أنها من علامة تجارية لكن المرسل مختلف",
        "The sender IP address is invalid": "عنوان IP للمرسل غير صالح",
        "The sender IP address is not routable": "لا يمكن توجيه عنوان IP للمرسل",
        "The sender IP has no verified reverse name": "لا يوجد اسم عكسي موثّق لعنوان IP للمرسل",
        "The sender comes from a residential-style address": "يبدو أن المرسل يستخدم عنواناً سكنياً",
        "The sender IP and domain do not seem to belong together": "يبدو أن عنوان IP للمرسل والنطاق غير مرتبطين",
        "The recipient IP address is invalid": "عنوان IP للمستلم غير صالح",
        "The recipient IP address is unusual": "عنوان IP للمستلم غير معتاد",
        "Sender and recipient share the same IP address": "يشترك المرسل والمستلم في عنوان IP نفسه",
        "The Reply-To address looks incomplete": "يبدو عنوان الرد غير مكتمل",
        "The Reply-To address imitates a trusted brand": "يقلد عنوان الرد علامة تجارية موثوقة",
        "Replies would go somewhere other than the sender": "ستُرسل الردود إلى عنوان غير عنوان المرسل",
        "Replies would go to a personal email provider": "ستُرسل الردود إلى مزود بريد شخصي",
        "The reply chain cannot be verified": "تعذّر التحقق من سلسلة الردود",
        "The message uses a financial pretext": "تستخدم الرسالة ذريعة مالية",
        "The reply chain pushes a financial request": "تتضمن سلسلة الردود طلباً مالياً",
        "The reply chain switches to a different domain": "تنتقل سلسلة الردود إلى نطاق مختلف",
        "An attachment may be unsafe": "قد يكون المرفق غير آمن",
        "An attachment can run code in a browser": "يمكن للمرفق تشغيل تعليمات برمجية في المتصفح",
        "An attachment is a disk image": "المرفق صورة قرص",
        "An attachment is a compressed archive": "المرفق أرشيف مضغوط",
        "A filename hides its real file type": "يخفي اسم الملف نوعه الحقيقي",
        "The message encourages opening a risky file in a browser": "تشجع الرسالة على فتح ملف خطير في المتصفح",
        "The message uses a document-related story to promote an attachment": "تستخدم الرسالة قصة عن مستند للتشجيع على فتح مرفق",
    },
    "Spanish": {
        "The sender is missing": "Falta la dirección del remitente",
        "The sender address looks incomplete": "La dirección del remitente parece incompleta",
        "The sender address looks suspicious": "La dirección del remitente parece sospechosa",
        "The domain may try to look familiar": "El dominio podría imitar uno conocido",
        "The sender uses a commonly abused domain ending": "El remitente usa una terminación de dominio frecuentemente abusada",
        "A personal email provider is posing as a business": "Un proveedor de correo personal suplanta a una empresa",
        "The sender domain is unusual": "El dominio del remitente es inusual",
        "The subject creates urgency": "El asunto intenta generar urgencia",
        "The subject uses lots of capital letters": "El asunto usa muchas mayúsculas",
        "The subject uses unusual punctuation": "El asunto usa puntuación inusual",
        "A link is hiding its real destination": "Un enlace oculta su destino real",
        "A link appears designed to hide its true address": "Un enlace parece diseñado para ocultar su dirección",
        "A link may imitate a trusted website": "Un enlace podría imitar un sitio de confianza",
        "A link imitates a familiar brand": "Un enlace imita una marca conocida",
        "The link uses a commonly abused domain ending": "El enlace usa una terminación de dominio frecuentemente abusada",
        "The link does not use HTTPS": "El enlace no usa HTTPS",
        "The link has an unusually complex address": "El enlace tiene una dirección inusualmente compleja",
        "The link does not match the sender": "El enlace no coincide con el remitente",
        "The message uses familiar phishing language": "El mensaje usa expresiones habituales de phishing",
        "The message asks for private information": "El mensaje solicita información privada",
        "The message claims to be from a brand but differs from the sender": "El mensaje dice ser de una marca, pero el remitente no coincide",
        "The sender IP address is invalid": "La dirección IP del remitente no es válida",
        "The sender IP address is not routable": "La dirección IP del remitente no es enrutable",
        "The sender IP has no verified reverse name": "La IP del remitente no tiene un nombre inverso verificado",
        "The sender comes from a residential-style address": "El remitente parece usar una dirección residencial",
        "The sender IP and domain do not seem to belong together": "La IP del remitente y el dominio no parecen estar relacionados",
        "The recipient IP address is invalid": "La dirección IP del destinatario no es válida",
        "The recipient IP address is unusual": "La dirección IP del destinatario es inusual",
        "Sender and recipient share the same IP address": "El remitente y el destinatario comparten la misma IP",
        "The Reply-To address looks incomplete": "La dirección de respuesta parece incompleta",
        "The Reply-To address imitates a trusted brand": "La dirección de respuesta imita una marca de confianza",
        "Replies would go somewhere other than the sender": "Las respuestas se enviarían a una dirección distinta del remitente",
        "Replies would go to a personal email provider": "Las respuestas irían a un proveedor de correo personal",
        "The reply chain cannot be verified": "No se puede verificar el hilo de respuestas",
        "The message uses a financial pretext": "El mensaje usa un pretexto financiero",
        "The reply chain pushes a financial request": "El hilo de respuestas promueve una solicitud financiera",
        "The reply chain switches to a different domain": "El hilo de respuestas cambia a otro dominio",
        "An attachment may be unsafe": "Un archivo adjunto podría ser peligroso",
        "An attachment can run code in a browser": "Un archivo adjunto puede ejecutar código en un navegador",
        "An attachment is a disk image": "El archivo adjunto es una imagen de disco",
        "An attachment is a compressed archive": "El archivo adjunto es un archivo comprimido",
        "A filename hides its real file type": "El nombre oculta el tipo real del archivo",
        "The message encourages opening a risky file in a browser": "El mensaje anima a abrir un archivo peligroso en un navegador",
        "The message uses a document-related story to promote an attachment": "El mensaje usa una historia sobre documentos para promover un adjunto",
    },
    "French": {
        "The sender is missing": "L’adresse de l’expéditeur est manquante",
        "The sender address looks incomplete": "L’adresse de l’expéditeur semble incomplète",
        "The sender address looks suspicious": "L’adresse de l’expéditeur semble suspecte",
        "The domain may try to look familiar": "Le domaine peut imiter un domaine connu",
        "The sender uses a commonly abused domain ending": "L’expéditeur utilise une extension de domaine souvent détournée",
        "A personal email provider is posing as a business": "Un service de messagerie personnel se fait passer pour une entreprise",
        "The sender domain is unusual": "Le domaine de l’expéditeur est inhabituel",
        "The subject creates urgency": "L’objet cherche à créer un sentiment d’urgence",
        "The subject uses lots of capital letters": "L’objet utilise beaucoup de majuscules",
        "The subject uses unusual punctuation": "L’objet utilise une ponctuation inhabituelle",
        "A link is hiding its real destination": "Un lien masque sa destination réelle",
        "A link appears designed to hide its true address": "Un lien semble conçu pour masquer sa véritable adresse",
        "A link may imitate a trusted website": "Un lien peut imiter un site de confiance",
        "A link imitates a familiar brand": "Un lien imite une marque connue",
        "The link uses a commonly abused domain ending": "Le lien utilise une extension de domaine souvent détournée",
        "The link does not use HTTPS": "Le lien n’utilise pas HTTPS",
        "The link has an unusually complex address": "Le lien possède une adresse inhabituellement complexe",
        "The link does not match the sender": "Le lien ne correspond pas à l’expéditeur",
        "The message uses familiar phishing language": "Le message utilise des expressions courantes d’hameçonnage",
        "The message asks for private information": "Le message demande des informations privées",
        "The message claims to be from a brand but differs from the sender": "Le message prétend provenir d’une marque, mais l’expéditeur diffère",
        "The sender IP address is invalid": "L’adresse IP de l’expéditeur est invalide",
        "The sender IP address is not routable": "L’adresse IP de l’expéditeur n’est pas routable",
        "The sender IP has no verified reverse name": "L’adresse IP de l’expéditeur n’a pas de nom inverse vérifié",
        "The sender comes from a residential-style address": "L’expéditeur semble utiliser une adresse résidentielle",
        "The sender IP and domain do not seem to belong together": "L’adresse IP et le domaine de l’expéditeur semblent sans lien",
        "The recipient IP address is invalid": "L’adresse IP du destinataire est invalide",
        "The recipient IP address is unusual": "L’adresse IP du destinataire est inhabituelle",
        "Sender and recipient share the same IP address": "L’expéditeur et le destinataire partagent la même adresse IP",
        "The Reply-To address looks incomplete": "L’adresse de réponse semble incomplète",
        "The Reply-To address imitates a trusted brand": "L’adresse de réponse imite une marque de confiance",
        "Replies would go somewhere other than the sender": "Les réponses seraient envoyées ailleurs qu’à l’expéditeur",
        "Replies would go to a personal email provider": "Les réponses seraient envoyées à un service de messagerie personnel",
        "The reply chain cannot be verified": "Le fil de discussion ne peut pas être vérifié",
        "The message uses a financial pretext": "Le message utilise un prétexte financier",
        "The reply chain pushes a financial request": "Le fil de discussion pousse à une demande financière",
        "The reply chain switches to a different domain": "Le fil de discussion passe à un autre domaine",
        "An attachment may be unsafe": "Une pièce jointe peut être dangereuse",
        "An attachment can run code in a browser": "Une pièce jointe peut exécuter du code dans un navigateur",
        "An attachment is a disk image": "La pièce jointe est une image disque",
        "An attachment is a compressed archive": "La pièce jointe est une archive compressée",
        "A filename hides its real file type": "Le nom du fichier masque son véritable type",
        "The message encourages opening a risky file in a browser": "Le message incite à ouvrir un fichier risqué dans un navigateur",
        "The message uses a document-related story to promote an attachment": "Le message utilise un prétexte lié à un document pour inciter à ouvrir une pièce jointe",
    },
}

VERDICTS = {
    "English": ("This email looks dangerous", "This email needs a closer look", "No clear warning signs found"),
    "Arabic": ("يبدو هذا البريد الإلكتروني خطيراً", "يحتاج هذا البريد الإلكتروني إلى مزيد من التحقق",
               "لم يتم العثور على مؤشرات تحذير واضحة"),
    "Spanish": ("Este correo parece peligroso", "Este correo requiere una revisión más detallada",
                "No se encontraron señales de alerta claras"),
    "French": ("Cet e-mail semble dangereux", "Cet e-mail mérite une vérification approfondie",
               "Aucun signe d’alerte clair détecté"),
}

NEXT_STEPS = {
    "English": (
        "Do not open links or attachments. Verify it another way before replying.",
        "Pause and verify the sender before taking any action.",
        "It appears okay, but still use normal caution with links and attachments.",
    ),
    "Arabic": (
        "لا تفتح الروابط أو المرفقات. تحقق من الرسالة بطريقة أخرى قبل الرد.",
        "توقف وتحقق من هوية المرسل قبل اتخاذ أي إجراء.",
        "تبدو الرسالة سليمة، لكن توخ الحذر المعتاد مع الروابط والمرفقات.",
    ),
    "Spanish": (
        "No abras enlaces ni archivos adjuntos. Verifica el mensaje por otro medio antes de responder.",
        "Haz una pausa y verifica al remitente antes de actuar.",
        "Parece correcto, pero mantén la precaución habitual con enlaces y adjuntos.",
    ),
    "French": (
        "N’ouvrez aucun lien ni pièce jointe. Vérifiez le message autrement avant de répondre.",
        "Prenez le temps de vérifier l’expéditeur avant d’agir.",
        "Le message semble acceptable, mais restez prudent avec les liens et les pièces jointes.",
    ),
}

SEVERITIES = {
    "English": {"Urgent": "Important", "High": "Strong warning", "Moderate": "Worth attention", "Low": "Minor clue"},
    "Arabic": {"Urgent": "مهم", "High": "تحذير قوي", "Moderate": "يستحق الانتباه", "Low": "مؤشر بسيط"},
    "Spanish": {"Urgent": "Importante", "High": "Advertencia importante", "Moderate": "Requiere atención", "Low": "Indicio menor"},
    "French": {"Urgent": "Important", "High": "Avertissement fort", "Moderate": "À surveiller", "Low": "Indice mineur"},
}


def ui_text(language: str, key: str) -> str:
    return UI_TEXT[language][key]


def finding_title(title: str, language: str) -> str:
    english_title = _ENGLISH_FINDING_TITLES.get(title, title.replace("_", " ").title())
    return LOCALIZED_FINDING_TITLES.get(language, {}).get(english_title, english_title)


def finding_detail(detail: str, language: str) -> str:
    if language == "English":
        return detail
    evidence = re.findall(r'"([^"]+)"', detail)
    if not evidence:
        return ""
    return f"{ui_text(language, 'evidence')}: {', '.join(evidence)}"


_ENGLISH_FINDING_TITLES = {
    "MISSING SENDER": "The sender is missing",
    "INVALID SENDER": "The sender address looks incomplete",
    "SUSPICIOUS SENDER": "The sender address looks suspicious",
    "HOMOGRAPH DOMAIN": "The domain may try to look familiar",
    "RISKY TLD": "The sender uses a commonly abused domain ending",
    "FREE-MAIL IMPERSONATION": "A personal email provider is posing as a business",
    "ODD DOMAIN": "The sender domain is unusual",
    "URGENT SUBJECT LINE": "The subject creates urgency",
    "SHOUTING SUBJECT": "The subject uses lots of capital letters",
    "EXCESSIVE PUNCTUATION": "The subject uses unusual punctuation",
    "UNTRUSTED LINKS": "A link is hiding its real destination",
    "DECEPTIVE LINK": "A link appears designed to hide its true address",
    "HOMOGRAPH LINK": "A link may imitate a trusted website",
    "LOOKALIKE LINK": "A link imitates a familiar brand",
    "RISKY LINK TLD": "The link uses a commonly abused domain ending",
    "INSECURE LINK": "The link does not use HTTPS",
    "DEEP SUBDOMAIN": "The link has an unusually complex address",
    "MISMATCHED LINK": "The link does not match the sender",
    "SPAM KEYWORDS": "The message uses familiar phishing language",
    "CREDENTIAL REQUEST": "The message asks for private information",
    "IDENTITY MISMATCH": "The message claims to be from a brand but differs from the sender",
    "INVALID SENDER IP": "The sender IP address is invalid",
    "NON-ROUTABLE SENDER IP": "The sender IP address is not routable",
    "NO REVERSE DNS": "The sender IP has no verified reverse name",
    "DYNAMIC / RESIDENTIAL IP": "The sender comes from a residential-style address",
    "IP / DOMAIN MISMATCH": "The sender IP and domain do not seem to belong together",
    "INVALID RECIPIENT IP": "The recipient IP address is invalid",
    "ODD RECIPIENT IP": "The recipient IP address is unusual",
    "SAME SENDER / RECIPIENT IP": "Sender and recipient share the same IP address",
    "INVALID REPLY-TO": "The Reply-To address looks incomplete",
    "LOOKALIKE REPLY-TO": "The Reply-To address imitates a trusted brand",
    "REPLY-TO MISMATCH": "Replies would go somewhere other than the sender",
    "FREE-MAIL REPLY-TO": "Replies would go to a personal email provider",
    "UNVERIFIABLE REPLY CHAIN": "The reply chain cannot be verified",
    "FINANCIAL PRETEXT": "The message uses a financial pretext",
    "FINANCIAL REPLY LURE": "The reply chain pushes a financial request",
    "THREAD DOMAIN SWITCH": "The reply chain switches to a different domain",
    "RISKY ATTACHMENT": "An attachment may be unsafe",
    "SCRIPTABLE ATTACHMENT": "An attachment can run code in a browser",
    "DISK-IMAGE ATTACHMENT": "An attachment is a disk image",
    "ARCHIVE ATTACHMENT": "An attachment is a compressed archive",
    "DOUBLE EXTENSION": "A filename hides its real file type",
    "HTML SMUGGLING LURE": "The message encourages opening a risky file in a browser",
    "DOCUMENT LURE": "The message uses a document-related story to promote an attachment",
}


def verdict_text(verdict: str, language: str) -> str:
    dangerous, suspicious, safe = VERDICTS[language]
    if verdict.startswith("HIGH"):
        return dangerous
    if verdict == "SUSPICIOUS":
        return suspicious
    return safe


def next_step_text(verdict: str, language: str) -> str:
    dangerous, suspicious, safe = NEXT_STEPS[language]
    if verdict.startswith("HIGH"):
        return dangerous
    if verdict == "SUSPICIOUS":
        return suspicious
    return safe


def severity_text(severity: str, language: str) -> str:
    return SEVERITIES[language].get(severity, severity)


def report_info_text(text: str, language: str) -> str:
    if language == "English":
        return text.strip()
    line = text.strip()
    reply = re.fullmatch(r'Reply/forward detected \("(.+)", (\d+) prefix\(es\)\)\.', line)
    if reply:
        return ui_text(language, "thread_reply").format(subject=reply.group(1), count=reply.group(2))
    if line == "Not a reply (no Re:/Fw: prefix).":
        return ui_text(language, "thread_not_reply")
    quoted = re.fullmatch(
        r"Earlier messages quoted in the body: (yes|none)\. Newest message analyzed: (\d+) characters\.",
        line,
    )
    if quoted:
        quoted_value = ui_text(language, "quoted_yes" if quoted.group(1) == "yes" else "quoted_none")
        return ui_text(language, "thread_quoted").format(
            quoted=quoted_value, characters=quoted.group(2)
        )
    for label, key in (("Sender IP ", "sender_ip_info"),
                       ("Recipient IP ", "recipient_ip_info")):
        if line.startswith(label) and ": " in line:
            ip, kind = line[len(label):].split(": ", 1)
            translated_kind = _IP_KIND_TRANSLATIONS[language].get(kind, kind)
            return ui_text(language, key).format(ip=ip, kind=translated_kind)
    if line == "reverse DNS: unavailable (offline or timed out)":
        return ui_text(language, "rdns_unavailable")
    if line == "reverse DNS: none (no PTR record)":
        return ui_text(language, "rdns_none")
    if line.startswith("reverse DNS: "):
        return ui_text(language, "rdns_found").format(hostname=line[len("reverse DNS: "):])
    return line


def translated_detection_phrases(language: str, category: str) -> tuple:
    return DETECTION_PHRASES[language][category]


_IP_KIND_TRANSLATIONS = {
    "Arabic": {
        "public": "عام",
        "loopback": "استرجاع",
        "link-local": "ارتباط محلي",
        "multicast": "بث متعدد",
        "unspecified": "غير محدد",
        "private / reserved range": "نطاق خاص أو محجوز",
        "reserved": "محجوز",
    },
    "Spanish": {
        "public": "pública",
        "loopback": "bucle local",
        "link-local": "enlace local",
        "multicast": "multidifusión",
        "unspecified": "no especificada",
        "private / reserved range": "rango privado o reservado",
        "reserved": "reservada",
    },
    "French": {
        "public": "publique",
        "loopback": "boucle locale",
        "link-local": "liaison locale",
        "multicast": "multidiffusion",
        "unspecified": "non spécifiée",
        "private / reserved range": "plage privée ou réservée",
        "reserved": "réservée",
    },
}


# ----------------------------------------------------------------- severities
URGENT, HIGH, MODERATE, LOW = "Urgent", "High", "Moderate", "Low"
SEVERITY_POINTS = {URGENT: 35, HIGH: 20, MODERATE: 10, LOW: 4}

# ------------------------------------------------------------------ word lists
FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "mail.com", "proton.me", "protonmail.com", "gmx.com", "icloud.com",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "bl.ink",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "work", "gq", "tk", "ml", "cf", "ga",
    "zip", "mov", "rest", "country", "kim", "loan", "men", "support", "icu",
}
# brand -> legitimate registrable domains
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de"},
    "google": {"google.com", "gmail.com"},
    "facebook": {"facebook.com", "meta.com", "facebookmail.com"},
    "netflix": {"netflix.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "binance": {"binance.com"},
    "dropbox": {"dropbox.com"},
}
LOOKALIKE_WORDS = ("verify", "secure", "security", "login", "signin", "account",
                   "update", "support", "service", "billing", "confirm", "alert")

SUBJECT_TRIGGERS = [
    "urgent", "immediate action", "action required", "suspended", "suspension",
    "verify", "account locked", "locked", "unusual activity", "final notice",
    "last warning", "expires", "terminated", "security alert", "confirm your",
    "limited", "payment failed", "you have won", "winner", "invoice overdue",
]
BODY_PHRASES = [
    "immediately confirm", "confirm your identity", "verify your account",
    "verify your identity", "within 24 hours", "within 48 hours", "click here",
    "click the link", "click below", "account will be", "account access",
    "terminated", "suspended", "unauthorized access", "unusual activity",
    "reset your password", "update your payment", "update your billing",
    "login credentials", "social security", "wire transfer", "gift card",
    "crypto", "bitcoin", "you have won", "claim your", "act now", "dear customer",
    "dear user", "kindly", "password expires", "enter your password",
]

URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\[\]\"'()]+)")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})$")
SIGNOFF_RE = re.compile(r"(?i)(?:sincerely|regards|thanks|thank you|best)[,\s]*\n+\s*(.+)")


@dataclass
class Finding:
    title: str
    detail: str
    severity: str

    @property
    def points(self):
        return SEVERITY_POINTS[self.severity]


@dataclass
class Report:
    verdict: str = "SAFE"
    score: int = 0
    findings: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    ip_info: list = field(default_factory=list)
    thread_info: list = field(default_factory=list)
    language: str = "English"

    def as_text(self, sender="", recipient="", subject="", reply_to="", attachments="",
                language=None):
        language = language or self.language
        lines = [
            ui_text(language, "report_title"),
            "=" * 40,
            f"{ui_text(language, 'from')}:    {sender}",
            f"{ui_text(language, 'to')}:      {recipient}",
            f"{ui_text(language, 'reply_to_report')}: {reply_to or ui_text(language, 'no_value')}",
            f"{ui_text(language, 'subject_report')}: {subject}",
            f"{ui_text(language, 'attachments_report')}: "
            f"{attachments or ui_text(language, 'none_listed')}",
            "",
            f"{ui_text(language, 'result')}: {human_verdict(self.verdict, language)}",
            f"{ui_text(language, 'risk_score')}: {self.score}/100",
            "",
            ui_text(language, "noticed"),
        ]
        if self.findings:
            for f in self.findings:
                title = human_finding_title(f.title, language)
                detail = human_finding_detail(f.detail, language)
                severity = human_severity(f.severity, language)
                description = f": {detail}" if detail else ""
                lines.append(f" - {title}{description} [{severity}]")
        else:
            lines.append(ui_text(language, "no_findings").strip())
        if self.thread_info:
            lines += ["", ui_text(language, "thread_info")] + [
                f" - {report_info_text(i, language)}" for i in self.thread_info
            ]
        if self.ip_info:
            lines += ["", ui_text(language, "ip_info")] + [
                f" - {report_info_text(i, language)}" for i in self.ip_info
            ]
        if self.urls:
            lines += ["", ui_text(language, "links_checked")] + [f" - {u}" for u in self.urls]
        lines += [
            "",
            ui_text(language, "next_step"),
            human_next_step(self.verdict, language),
            "",
            ui_text(language, "disclaimer"),
        ]
        return "\n".join(lines)


# --------------------------------------------------------------------- helpers
def registrable_domain(host: str) -> str:
    """Last two labels (good enough without a public-suffix list)."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def normalize_leet(text: str) -> str:
    return text.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s",
                                         "8": "b", "$": "s", "|": "l"}))


def brand_in(text: str):
    low = text.lower()
    leet = normalize_leet(low)
    for brand in BRANDS:
        if brand in low or brand in leet:
            return brand
    return None


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def human_verdict(verdict: str, language: str = "English") -> str:
    return verdict_text(verdict, language)


def human_next_step(verdict: str, language: str = "English") -> str:
    return next_step_text(verdict, language)


def human_finding_title(title: str, language: str = "English") -> str:
    return finding_title(title, language)


def human_finding_detail(detail: str, language: str = "English") -> str:
    return finding_detail(detail, language)


def human_severity(severity: str, language: str = "English") -> str:
    return severity_text(severity, language)


# ----------------------------------------------------------------- the checks
def check_sender(sender: str):
    out = []
    sender = sender.strip()
    if not sender:
        return [Finding("MISSING SENDER", "No sender address supplied.", MODERATE)], None
    m = EMAIL_RE.match(sender.split("<")[-1].strip(" >") if "<" in sender else sender)
    if not m:
        return [Finding("INVALID SENDER", f'"{sender}" is not a valid email address.', HIGH)], None
    domain = m.group(1).lower()
    reg = registrable_domain(domain)
    local = sender.split("@")[0].lower()
    tld = domain.rsplit(".", 1)[-1]

    brand = brand_in(domain)
    if brand and reg not in BRANDS[brand]:
        out.append(Finding("SUSPICIOUS SENDER",
                           f'Domain "{domain}" imitates {brand.title()} but is not an official {brand.title()} domain.',
                           URGENT))
    elif any(w in reg.split(".")[0] for w in LOOKALIKE_WORDS) and "-" in reg.split(".")[0]:
        out.append(Finding("SUSPICIOUS SENDER",
                           f'Domain "{domain}" uses a hyphenated "security/verify" style name common in phishing.',
                           HIGH))
    if domain.startswith("xn--") or ".xn--" in domain or not domain.isascii():
        out.append(Finding("HOMOGRAPH DOMAIN", f'"{domain}" uses punycode / non-ASCII characters to mimic another site.', URGENT))
    if tld in SUSPICIOUS_TLDS:
        out.append(Finding("RISKY TLD", f'Sender TLD ".{tld}" is heavily abused for throw-away phishing domains.', MODERATE))
    if reg in FREE_MAIL and any(w in local for w in ("support", "security", "admin", "billing", "service", "helpdesk", "noreply")):
        out.append(Finding("FREE-MAIL IMPERSONATION",
                           f'Official-looking name "{local}" sent from free provider {reg}.', HIGH))
    if re.search(r"\d{4,}", domain):
        out.append(Finding("ODD DOMAIN", "Sender domain contains a long digit sequence.", LOW))
    return out, domain


def check_subject(subject: str, language: str = "English"):
    low = subject.lower()
    triggers = SUBJECT_TRIGGERS + list(translated_detection_phrases(language, "subject"))
    hits = [t for t in triggers if t in low]
    out = []
    if hits:
        out.append(Finding("URGENT SUBJECT LINE",
                           "Subject triggers social-engineering detection (" + ", ".join(f'"{h}"' for h in hits[:4]) + ").",
                           MODERATE if len(hits) < 3 else HIGH))
    letters = [c for c in subject if c.isalpha()]
    if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        out.append(Finding("SHOUTING SUBJECT", "Subject is mostly capital letters.", LOW))
    if subject.count("!") >= 2:
        out.append(Finding("EXCESSIVE PUNCTUATION", "Multiple exclamation marks in subject.", LOW))
    return out


def extract_urls(body: str):
    seen, urls = set(), []
    for raw in URL_RE.findall(body):
        u = raw.rstrip(".,;:!?]")
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def check_links(urls, sender_domain):
    out = []
    for u in urls:
        full = u if u.lower().startswith("http") else "http://" + u
        p = urlparse(full)
        host = (p.hostname or "").lower()
        if not host:
            continue
        reg = registrable_domain(host)
        tld = host.rsplit(".", 1)[-1]
        if reg in URL_SHORTENERS or host in URL_SHORTENERS:
            out.append(Finding("UNTRUSTED LINKS", f'Shortened URL "{u}" hides the real destination.', URGENT))
            continue
        if is_ip(host):
            out.append(Finding("UNTRUSTED LINKS", f'Link "{u}" points to a raw IP address.', URGENT))
            continue
        if "@" in p.netloc:
            out.append(Finding("DECEPTIVE LINK", f'"{u}" contains "@" to disguise the true host.', URGENT))
        if host.startswith("xn--") or ".xn--" in host:
            out.append(Finding("HOMOGRAPH LINK", f'"{host}" uses punycode to mimic another site.', URGENT))
        brand = brand_in(host)
        if brand and reg not in BRANDS[brand]:
            out.append(Finding("LOOKALIKE LINK", f'"{host}" imitates {brand.title()} but is not an official domain.', URGENT))
        if tld in SUSPICIOUS_TLDS:
            out.append(Finding("RISKY LINK TLD", f'Link uses ".{tld}" domain ({host}).', MODERATE))
        if p.scheme == "http":
            out.append(Finding("INSECURE LINK", f'"{host}" is not served over HTTPS.', LOW))
        if host.count(".") >= 4:
            out.append(Finding("DEEP SUBDOMAIN", f'"{host}" has an unusually long subdomain chain.', MODERATE))
        if sender_domain and reg != registrable_domain(sender_domain) and any(
                w in host for w in LOOKALIKE_WORDS) and "-" in host:
            out.append(Finding("MISMATCHED LINK", f'Link domain "{host}" does not match sender domain.', MODERATE))
    return out


def check_body(body: str, subject: str, language: str = "English"):
    low = body.lower()
    phrases = BODY_PHRASES + list(translated_detection_phrases(language, "body"))
    hits = [p for p in phrases if p in low]
    out = []
    if hits:
        shown = ", ".join(f'"{h}"' for h in hits[:4])
        sev = HIGH if len(hits) >= 3 else MODERATE
        out.append(Finding("SPAM KEYWORDS", f"Detects {len(hits)} phishing indicator(s) (e.g., {shown}).", sev))
    credential_terms = ("password", "ssn", "credit card", "card number", "pin", "cvv")
    credential_terms += translated_detection_phrases(language, "credentials")
    credential_pattern = r"(?i)(" + "|".join(re.escape(term) for term in credential_terms) + r")"
    if re.search(credential_pattern, body) and URL_RE.search(body):
        out.append(Finding("CREDENTIAL REQUEST", "Message asks for sensitive data and includes a link.", HIGH))
    return out


def check_identity(sender_domain, body):
    """Body claims to be brand X but sender domain isn't brand X."""
    if not sender_domain:
        return []
    m = SIGNOFF_RE.search(body)
    claimed = brand_in(m.group(1)) if m else None
    if not claimed:
        claimed = brand_in(body[:300])
    if claimed and registrable_domain(sender_domain) not in BRANDS[claimed]:
        return [Finding("IDENTITY MISMATCH",
                        f'Email claims to be from {claimed.title()} but was sent from "{sender_domain}".', HIGH)]
    return []


# ------------------------------------------------------------------ IP checks
DYNAMIC_HINTS = ("dyn", "dynamic", "dhcp", "pool", "dsl", "adsl", "cable", "ppp",
                 "broadband", "residential", "cust", "client", "pppoe", "static-ip")


def parse_ip(text: str):
    try:
        return ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return None


def classify_ip(ip) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private / reserved range"
    if ip.is_reserved:
        return "reserved"
    return "public"


def resolve_rdns(ips, timeout: float = 3.0) -> dict:
    """Reverse-DNS each public IP. Never raises.

    value = hostname  -> PTR record found
            ""        -> lookup worked, but no PTR record exists
            None      -> skipped / timed out / DNS unavailable (unknown)
    """
    wanted = []
    for raw in ips:
        ip = parse_ip(raw) if raw and raw.strip() else None
        if ip is not None and ip.is_global:
            wanted.append(str(ip))
    result = {str(parse_ip(r)): None for r in ips if r and parse_ip(r)}
    if not wanted:
        return result

    def one(ip):
        try:
            return socket.gethostbyaddr(ip)[0].lower()
        except socket.herror:
            return ""            # definitively no PTR
        except Exception:
            return None          # resolver problem -> unknown

    def control():
        # Offline resolvers also raise "unknown host", which looks exactly like a
        # missing PTR. If a well-known name won't resolve, DNS is down: trust nothing.
        try:
            socket.gethostbyname("example.com")
            return True
        except Exception:
            return False

    ex = ThreadPoolExecutor(max_workers=len(wanted) + 1)
    ctrl = ex.submit(control)
    futs = {ip: ex.submit(one, ip) for ip in wanted}
    try:
        dns_ok = ctrl.result(timeout=timeout)
    except Exception:
        dns_ok = False
    for ip, fut in futs.items():
        try:
            val = fut.result(timeout=timeout)
        except Exception:
            val = None
        result[ip] = val if (dns_ok or val) else None   # a real hostname is always believable
    ex.shutdown(wait=False)
    return result


def _rdns_line(ip, rdns):
    host = rdns.get(str(ip))
    if host is None:
        return "reverse DNS: unavailable (offline or timed out)"
    return f"reverse DNS: {host}" if host else "reverse DNS: none (no PTR record)"


def check_ips(sender_ip, recipient_ip, sender_domain, rdns):
    """Returns (findings, info_lines). Both IPs are optional."""
    out, info, rdns = [], [], rdns or {}
    s = r = None

    if sender_ip.strip():
        s = parse_ip(sender_ip)
        if s is None:
            out.append(Finding("INVALID SENDER IP", f'"{sender_ip}" is not a valid IPv4/IPv6 address.', MODERATE))
        else:
            kind = classify_ip(s)
            info.append(f"Sender IP {s}: {kind}")
            if kind != "public":
                out.append(Finding("NON-ROUTABLE SENDER IP",
                                   f"Sender IP {s} is {kind}; a genuine external email cannot originate from it (forged header?).",
                                   HIGH))
            else:
                info.append("  " + _rdns_line(s, rdns))
                host = rdns.get(str(s))
                if host == "":
                    out.append(Finding("NO REVERSE DNS",
                                       f"Sender IP {s} has no PTR record - typical of compromised or throw-away hosts.",
                                       MODERATE))
                elif host:
                    octets = [o for o in re.split(r"[.:]", str(s)) if o]
                    dashed = "-".join(octets)
                    if any(h in host for h in DYNAMIC_HINTS) or dashed in host:
                        out.append(Finding("DYNAMIC / RESIDENTIAL IP",
                                           f'Sender host "{host}" looks like a home/dynamic connection, not a mail server.',
                                           MODERATE))
                    if (sender_domain and registrable_domain(sender_domain) not in FREE_MAIL
                            and registrable_domain(host) != registrable_domain(sender_domain)):
                        out.append(Finding("IP / DOMAIN MISMATCH",
                                           f'Sending host "{host}" is unrelated to sender domain "{sender_domain}" '
                                           f'(common with mail relays, so low weight).', LOW))

    if recipient_ip.strip():
        r = parse_ip(recipient_ip)
        if r is None:
            out.append(Finding("INVALID RECIPIENT IP", f'"{recipient_ip}" is not a valid IPv4/IPv6 address.', LOW))
        else:
            info.append(f"Recipient IP {r}: {classify_ip(r)}")
            if classify_ip(r) == "public":
                info.append("  " + _rdns_line(r, rdns))
            elif classify_ip(r) in ("loopback", "multicast", "unspecified"):
                out.append(Finding("ODD RECIPIENT IP", f"Recipient IP {r} is {classify_ip(r)} - unusual for a delivered email.", LOW))

    if s is not None and r is not None and s == r:
        out.append(Finding("SAME SENDER / RECIPIENT IP",
                           "Sender and recipient share one IP address - possible spoofed or self-sent mail.", MODERATE))
    return out, info


# ------------------------------------------------- header cleanup + Reply-To
ADDR_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
REPLY_TO_INLINE_RE = re.compile(r"(?i)\(?\s*reply[- ]?to\s*:\s*([^)\n]*)\)?")


def sanitize_header(raw: str):
    """Clean a pasted From value. Returns (clean_address, reply_to_found_inside_or_empty).

    Handles backticks/quotes, 'Name <addr>' form, and '(Reply-To: addr)' pasted into the field.
    """
    raw = (raw or "").strip()
    embedded = ""
    m = REPLY_TO_INLINE_RE.search(raw)
    if m:
        found = ADDR_RE.search(m.group(1))
        embedded = found.group(0) if found else m.group(1).strip()
        raw = (raw[:m.start()] + raw[m.end():]).strip()
    raw = raw.strip("`'\" \t")
    found = ADDR_RE.search(raw)
    return (found.group(0) if found else raw), embedded


def similar_domains(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()


def check_reply_to(reply_to: str, sender_domain):
    reply_to = (reply_to or "").strip().strip("`'\" ")
    if not reply_to:
        return []
    found = ADDR_RE.search(reply_to)
    if not found:
        return [Finding("INVALID REPLY-TO", f'"{reply_to}" is not a valid email address.', MODERATE)]
    rt_domain = found.group(0).split("@")[1].lower()
    rt_reg = registrable_domain(rt_domain)
    out = []
    if sender_domain:
        s_reg = registrable_domain(sender_domain)
        if rt_reg == s_reg:
            return out
        ratio = similar_domains(s_reg, rt_reg)
        if ratio >= 0.85:
            out.append(Finding("LOOKALIKE REPLY-TO",
                               f'Replies go to "{rt_domain}", a near-copy of the sender domain "{sender_domain}" '
                               f'({int(ratio * 100)}% identical) - typosquatting to hijack the conversation.', URGENT))
            return out
        out.append(Finding("REPLY-TO MISMATCH",
                           f'Replies go to "{rt_domain}", not the sender domain "{sender_domain}".', HIGH))
    if rt_reg in FREE_MAIL:
        out.append(Finding("FREE-MAIL REPLY-TO", f'Reply-To uses free provider {rt_reg}.', HIGH))
    return out


# ----------------------------------------------------------- reply-thread analysis
QUOTE_MARKERS = [
    re.compile(r"(?im)^\s*-{2,}\s*original message\s*-{2,}"),
    re.compile(r"(?im)^\s*-{2,}\s*forwarded message\s*-{2,}"),
    re.compile(r"(?im)^\s*begin forwarded message:"),
    re.compile(r"(?im)^\s*on .{5,160}wrote:\s*$"),
    re.compile(r"(?im)^\s*from:\s+.+\n\s*(?:sent|date):"),
    re.compile(r"(?m)^\s*>"),
]
REPLY_PREFIX_RE = re.compile(r"(?i)^\s*((?:re|fw|fwd)\s*:\s*)+")
PRETEXT = ["following up on our call", "following our call", "as discussed", "per our conversation",
           "per our call", "as we discussed", "as agreed", "as promised", "our call earlier",
           "following up on our conversation", "as per our discussion"]
FINANCE = ["remittance", "invoice", "statement", "ledger", "wire", "payment", "bank details",
           "routing number", "account number", "discrepancy", "reconcile", "reconciliation",
           "sign off", "signs off", "purchase order", "payroll", "direct deposit", "month-end",
           "line items", "balance due"]


def split_reply(body: str, language: str = "English"):
    """Split into (newest_message, quoted_history)."""
    cut = len(body)
    localized_markers = {
        "Arabic": (
            re.compile(r"(?im)^\s*-{2,}\s*(?:الرسالة الأصلية|رسالة معاد توجيهها)\s*-{2,}"),
            re.compile(r"(?im)^\s*من:\s+.+\n\s*(?:التاريخ|أرسلت):"),
        ),
        "Spanish": (
            re.compile(r"(?im)^\s*-{2,}\s*(?:mensaje original|mensaje reenviado)\s*-{2,}"),
            re.compile(r"(?im)^\s*el .{5,160} escribió:\s*$"),
            re.compile(r"(?im)^\s*de:\s+.+\n\s*(?:enviado|fecha):"),
        ),
        "French": (
            re.compile(r"(?im)^\s*-{2,}\s*(?:message d'origine|message transféré)\s*-{2,}"),
            re.compile(r"(?im)^\s*le .{5,160} a écrit\s*:\s*$"),
            re.compile(r"(?im)^\s*de\s*:\s+.+\n\s*(?:envoyé|date)\s*:"),
        ),
    }
    for rx in QUOTE_MARKERS + list(localized_markers.get(language, ())):
        m = rx.search(body)
        if m:
            cut = min(cut, m.start())
    return body[:cut].strip(), body[cut:].strip()


def check_thread(subject: str, new_text: str, quoted: str, sender_domain,
                 language: str = "English"):
    """Returns (findings, info_lines)."""
    out, info = [], []
    reply_token = {
        "Arabic": r"(?:re|fw|fwd|رد)",
        "Spanish": r"(?:re|rv|fw|fwd)",
        "French": r"(?:re|tr|fw|fwd)",
    }.get(language, r"(?:re|fw|fwd)")
    reply_prefix_re = re.compile(r"(?i)^\s*((?:" + reply_token + r")\s*:\s*)+")
    pm = reply_prefix_re.match(subject or "")
    is_reply = bool(pm)
    prefixes = len(re.findall(r"(?i)(?:" + reply_token + r")\s*:", pm.group(0))) if pm else 0

    if is_reply:
        info.append(f'Reply/forward detected ("{pm.group(0).strip()}", {prefixes} prefix(es)).')
    else:
        info.append("Not a reply (no Re:/Fw: prefix).")
    info.append("Earlier messages quoted in the body: " + ("yes" if quoted else "none") +
                f". Newest message analyzed: {len(new_text)} characters.")

    if is_reply and not quoted:
        extra = " Stacked Re:/FW: prefixes make it look like a long conversation." if prefixes >= 2 else ""
        out.append(Finding("UNVERIFIABLE REPLY CHAIN",
                           'Subject claims to be a reply/forward but the message contains no earlier thread, '
                           'so the history cannot be verified - typical of thread hijacking.' + extra, MODERATE))

    low = new_text.lower()
    pretext = PRETEXT + list(translated_detection_phrases(language, "pretext"))
    finance = FINANCE + list(translated_detection_phrases(language, "finance"))
    pre = [p for p in pretext if p in low]
    fin = [f for f in finance if f in low]
    if pre and fin:
        out.append(Finding("FINANCIAL PRETEXT",
                           f'Cites a prior conversation ("{pre[0]}") and pushes a financial action '
                           f'({", ".join(fin[:3])}) - classic business-email-compromise lure.', HIGH))
    elif len(fin) >= 3 and is_reply:
        out.append(Finding("FINANCIAL REPLY LURE",
                           f'Reply is dense with payment terms ({", ".join(fin[:3])}).', MODERATE))

    if quoted and sender_domain:
        s_reg = registrable_domain(sender_domain)
        for addr in set(re.findall(r"(?im)^\s*>*\s*from:.*?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})", quoted)):
            q_reg = registrable_domain(addr.split("@")[1])
            if q_reg != s_reg and similar_domains(s_reg, q_reg) >= 0.85:
                out.append(Finding("THREAD DOMAIN SWITCH",
                                   f'Earlier message in the thread came from "{q_reg}" but this reply comes from the '
                                   f'near-identical "{s_reg}".', URGENT))
    return out, info


EXEC_EXT = {"exe", "scr", "bat", "cmd", "pif", "js", "jse", "vbs", "vbe", "wsf",
            "jar", "lnk", "hta", "ps1", "msi"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlsb", "dotm", "xlam"}
SCRIPT_EXT = {"svg", "html", "htm", "xhtml", "shtml", "mht", "mhtml"}
DISK_EXT = {"iso", "img", "vhd", "vhdx"}
ARCHIVE_EXT = {"zip", "rar", "7z", "cab", "gz", "tar"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif", "txt", "rtf"}
RISKY_EXT = EXEC_EXT | MACRO_EXT | SCRIPT_EXT | DISK_EXT | ARCHIVE_EXT
AMBIGUOUS_EXT = SCRIPT_EXT | ARCHIVE_EXT
ATTACH_RE = re.compile(r"(?<![/\w\-.=?&#])([\w\-.()]{1,80}\.(?:"
                       + "|".join(sorted(RISKY_EXT, key=len, reverse=True)) + r"))\b(?![/\w])", re.I)
DOUBLE_EXT_RE = re.compile(r"\.(?:" + "|".join(DECOY_EXT) + r")\s*\.(?:" + "|".join(RISKY_EXT) + r")$", re.I)
BROWSER_OPEN = ("in your browser", "in a browser", "in the browser", "open in browser",
                "view in browser", "document viewer", "web viewer", "online viewer")
LURE_TERMS = ("fax", "facsimile", "voicemail", "voice message", "scanned", "secure document",
              "document viewer", "shared document", "secure message", "encrypted message")


def parse_attachment_list(raw: str):
    names = []
    for part in re.split(r"[,;\n|]+", raw or ""):
        name = part.strip().strip("`'\" ")
        if "." in name and name.rsplit(".", 1)[-1].isalnum():
            names.append(name)
    return names


def _attachment_kind(name: str):
    extension = name.lower().rsplit(".", 1)[-1]
    for kind, extensions in (("exec", EXEC_EXT), ("macro", MACRO_EXT), ("script", SCRIPT_EXT),
                             ("disk", DISK_EXT), ("archive", ARCHIVE_EXT)):
        if extension in extensions:
            return kind
    return None


def check_attachments(subject: str, text: str, listed: str = "",
                      language: str = "English"):
    """Review listed and mentioned risky attachments, plus common attachment lures."""
    low = text.lower()
    found = {}
    attachment_terms = translated_detection_phrases(language, "attachment")
    for name in parse_attachment_list(listed):
        kind = _attachment_kind(name)
        if kind:
            found.setdefault(name.lower(), (name, kind))
    for match in ATTACH_RE.finditer(text):
        name = match.group(1).strip("`'\" ")
        kind = _attachment_kind(name)
        if kind is None:
            continue
        if (name.lower().rsplit(".", 1)[-1] in AMBIGUOUS_EXT
                and not any(term in low for term in attachment_terms)):
            continue
        found.setdefault(name.lower(), (name, kind))

    findings, kinds = [], set()
    for name, kind in found.values():
        kinds.add(kind)
        if kind == "exec":
            findings.append(Finding(
                "RISKY ATTACHMENT",
                f'"{name}" is a program or script, which can run code if opened.',
                HIGH,
            ))
        elif kind == "macro":
            findings.append(Finding(
                "RISKY ATTACHMENT",
                f'"{name}" is an Office file that can run code if macros are enabled.',
                HIGH,
            ))
        elif kind == "script":
            findings.append(Finding(
                "SCRIPTABLE ATTACHMENT",
                f'"{name}" is an HTML/SVG file that can run JavaScript in a browser.',
                HIGH,
            ))
        elif kind == "disk":
            findings.append(Finding(
                "DISK-IMAGE ATTACHMENT",
                f'"{name}" is a disk image that can contain files hidden from basic checks.',
                HIGH,
            ))
        elif kind == "archive":
            findings.append(Finding(
                "ARCHIVE ATTACHMENT",
                f'"{name}" is a compressed archive, so its contents are not visible here.',
                MODERATE,
            ))
        if DOUBLE_EXT_RE.search(name):
            findings.append(Finding(
                "DOUBLE EXTENSION",
                f'"{name}" uses two extensions, which can disguise the file type.',
                URGENT,
            ))

    context = (subject + " " + text).lower()
    browser_open = BROWSER_OPEN + translated_detection_phrases(language, "browser")
    lure_terms = LURE_TERMS + translated_detection_phrases(language, "lure")
    if "script" in kinds and any(phrase in low for phrase in browser_open):
        findings.append(Finding(
            "HTML SMUGGLING LURE",
            "The message asks you to open an HTML/SVG file in a browser or viewer. "
            "That file may build another file in the browser.",
            URGENT,
        ))
    if kinds and any(term in context for term in lure_terms):
        findings.append(Finding(
            "DOCUMENT LURE",
            "The message uses a fax, voicemail, or document story alongside a risky attachment.",
            MODERATE,
        ))
    return findings


# ------------------------------------------------------------------ public API
STAGES = ("Checking sender...", "Scanning subject...", "Reading reply thread...",
          "Inspecting links...", "Testing IP addresses...", "Analyzing content...",
          "Cross-checking identity...", "Analysis Complete")


def analyze_steps(sender: str, recipient: str, subject: str, body: str,
                  sender_ip: str = "", recipient_ip: str = "", rdns: dict = None,
                  reply_to: str = "", attachments: str = "", language: str = "English"):
    """Generator yielding (stage_label, percent, report_or_None); report is set on the last yield."""
    report = Report(language=language)
    sender, embedded_rt = sanitize_header(sender)
    reply_to = (reply_to or "").strip() or embedded_rt

    f_sender, domain = check_sender(sender)
    f_reply_to = check_reply_to(reply_to, domain)
    yield STAGES[0], 10, None
    f_subject = check_subject(subject, language)
    yield STAGES[1], 20, None
    new_text, quoted = split_reply(body, language)
    f_thread, report.thread_info = check_thread(subject, new_text, quoted, domain, language)
    yield STAGES[2], 35, None
    report.urls = extract_urls(body)
    f_links = check_links(report.urls, domain)
    yield STAGES[3], 50, None
    f_ips, report.ip_info = check_ips(sender_ip, recipient_ip, domain, rdns)
    yield STAGES[4], 65, None
    f_body = check_body(new_text, subject, language)
    f_attach = check_attachments(subject, new_text, attachments, language)
    yield STAGES[5], 80, None
    f_ident = check_identity(domain, new_text)
    yield STAGES[6], 92, None

    order = {URGENT: 0, HIGH: 1, MODERATE: 2, LOW: 3}
    seen, findings = set(), []
    for f in (f_sender + f_reply_to + f_subject + f_thread + f_links + f_ips
              + f_body + f_attach + f_ident):
        key = (f.title, f.detail)
        if key not in seen:
            seen.add(key)
            findings.append(f)
    findings.sort(key=lambda f: order[f.severity])

    per_title, total = {}, 0
    for f in findings:
        n = per_title.get(f.title, 0)
        if n < 2:
            total += f.points
        per_title[f.title] = n + 1
    report.score = min(100, total)
    report.findings = findings
    report.verdict = ("HIGH-RISK / MALICIOUS" if report.score >= 60 else
                      "SUSPICIOUS" if report.score >= 25 else "SAFE")
    yield STAGES[7], 100, report


def analyze(sender: str, recipient: str, subject: str, body: str,
            sender_ip: str = "", recipient_ip: str = "", rdns: dict = None,
            reply_to: str = "", attachments: str = "", language: str = "English") -> Report:
    report = None
    for _, _, r in analyze_steps(sender, recipient, subject, body, sender_ip, recipient_ip, rdns,
                                 reply_to, attachments, language):
        report = r or report
    return report
