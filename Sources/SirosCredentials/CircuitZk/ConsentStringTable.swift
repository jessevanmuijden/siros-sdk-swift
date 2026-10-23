// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// GENERATED from siros-sdk-kotlin's SDK string resources (feat/circuit-zk-consent, sdk/wallet/src/main/res/values*/strings.xml,
// head 3ed335f) so both SDKs word the consent identically. The wording is APPROVED (leifj); do not edit by hand: change
// it in the Kotlin resources and regenerate. Arguments are positional (`%1$s`, `%2$d`), filled by `ConsentStringTable.text`.

/// The consent sentences the SDK owns, one key per sentence.
enum ConsentString: String, CaseIterable, Sendable {
    case title = "siros_consent_title"
    case share = "siros_consent_share"
    case cancel = "siros_consent_cancel"
    case verifierProve = "siros_consent_verifier_prove"
    case verifierShare = "siros_consent_verifier_share"
    case ageBetween = "siros_consent_age_between"
    case ageAtLeast = "siros_consent_age_at_least"
    case ageAtMost = "siros_consent_age_at_most"
    case pseudonymIssuer = "siros_consent_pseudonym_issuer"
    case pseudonym = "siros_consent_pseudonym"
    case footer = "siros_consent_footer"
    case claim = "siros_consent_claim"
    case legacyPseudonym = "siros_consent_legacy_pseudonym"
    case refusedConsentUnavailable = "siros_dcapi_refused_consent_unavailable"
    case refusedUserDeclined = "siros_dcapi_refused_user_declined"
    case predicateEq = "siros_consent_predicate_eq"
    case predicateNe = "siros_consent_predicate_ne"
    case predicateLt = "siros_consent_predicate_lt"
    case predicateLe = "siros_consent_predicate_le"
    case predicateGt = "siros_consent_predicate_gt"
    case predicateGe = "siros_consent_predicate_ge"
    case predicateIn = "siros_consent_predicate_in"
    case predicateDateEq = "siros_consent_predicate_date_eq"
    case predicateDateNe = "siros_consent_predicate_date_ne"
    case predicateDateLt = "siros_consent_predicate_date_lt"
    case predicateDateLe = "siros_consent_predicate_date_le"
    case predicateDateGt = "siros_consent_predicate_date_gt"
    case predicateDateGe = "siros_consent_predicate_date_ge"
    case predicateDateIn = "siros_consent_predicate_date_in"
}

enum ConsentStringTable {
    /// Locales with a translation; any other falls back to English.
    static let locales: [String] = ["en", "sv", "fi", "el", "pt"]

    static let table: [String: [ConsentString: String]] = [
        "en": [
            .title: "Confirm sharing",
            .share: "Share",
            .cancel: "Cancel",
            .verifierProve: "%1$s is asking you to prove:",
            .verifierShare: "%1$s is asking you to share:",
            .ageBetween: "You were born between %1$s and %2$s (about %3$d–%4$d years old). Your exact birth date is not shared.",
            .ageAtLeast: "You are at least %1$d years old. Your exact birth date is not shared.",
            .ageAtMost: "You are at most %1$d years old. Your exact birth date is not shared.",
            .pseudonymIssuer: "A pseudonym for %1$s is shared. You get the same pseudonym every time you visit this service, and a different one at every other service. The service that issued your credential can work out who this pseudonym belongs to.",
            .pseudonym: "A pseudonym for %1$s is shared. You get the same pseudonym every time you visit this service, and a different one at every other service.",
            .footer: "No other personal data is shared.",
            .claim: "The value of “%1$s” from your credential is shared.",
            .legacyPseudonym: "A pseudonym is shared with %1$s.",
            .refusedConsentUnavailable: "Your wallet cannot ask for your approval right now, so nothing was shared.",
            .refusedUserDeclined: "You did not approve this request, so nothing was shared.",
            .predicateEq: "%1$s is %2$s.",
            .predicateNe: "%1$s is not %2$s.",
            .predicateLt: "%1$s is less than %2$s.",
            .predicateLe: "%1$s is at most %2$s.",
            .predicateGt: "%1$s is greater than %2$s.",
            .predicateGe: "%1$s is at least %2$s.",
            .predicateIn: "%1$s is one of: %2$s.",
            .predicateDateEq: "%1$s is on %2$s.",
            .predicateDateNe: "%1$s is not on %2$s.",
            .predicateDateLt: "%1$s is before %2$s.",
            .predicateDateLe: "%1$s is on or before %2$s.",
            .predicateDateGt: "%1$s is after %2$s.",
            .predicateDateGe: "%1$s is on or after %2$s.",
            .predicateDateIn: "%1$s is one of the dates: %2$s.",
        ],
        "sv": [
            .title: "Bekräfta delning",
            .share: "Dela",
            .cancel: "Avbryt",
            .verifierProve: "%1$s ber dig bevisa:",
            .verifierShare: "%1$s ber dig dela:",
            .ageBetween: "Du är född mellan %1$s och %2$s (ungefär %3$d–%4$d år gammal). Ditt exakta födelsedatum delas inte.",
            .ageAtLeast: "Du är minst %1$d år gammal. Ditt exakta födelsedatum delas inte.",
            .ageAtMost: "Du är högst %1$d år gammal. Ditt exakta födelsedatum delas inte.",
            .pseudonymIssuer: "En pseudonym för %1$s delas. Du får samma pseudonym varje gång du besöker den här tjänsten och en annan pseudonym hos varje annan tjänst. Tjänsten som utfärdade ditt intyg kan ta reda på vem pseudonymen tillhör.",
            .pseudonym: "En pseudonym för %1$s delas. Du får samma pseudonym varje gång du besöker den här tjänsten och en annan pseudonym hos varje annan tjänst.",
            .footer: "Inga andra personuppgifter delas.",
            .claim: "Värdet för ”%1$s” från ditt intyg delas.",
            .legacyPseudonym: "En pseudonym delas med %1$s.",
            .refusedConsentUnavailable: "Din plånbok kan inte be om ditt godkännande just nu, så ingenting delades.",
            .refusedUserDeclined: "Du godkände inte begäran, så ingenting delades.",
            .predicateEq: "%1$s är %2$s.",
            .predicateNe: "%1$s är inte %2$s.",
            .predicateLt: "%1$s är mindre än %2$s.",
            .predicateLe: "%1$s är högst %2$s.",
            .predicateGt: "%1$s är större än %2$s.",
            .predicateGe: "%1$s är minst %2$s.",
            .predicateIn: "%1$s är något av: %2$s.",
            .predicateDateEq: "%1$s är den %2$s.",
            .predicateDateNe: "%1$s är inte den %2$s.",
            .predicateDateLt: "%1$s är före %2$s.",
            .predicateDateLe: "%1$s är den %2$s eller tidigare.",
            .predicateDateGt: "%1$s är efter %2$s.",
            .predicateDateGe: "%1$s är den %2$s eller senare.",
            .predicateDateIn: "%1$s är något av datumen: %2$s.",
        ],
        "fi": [
            .title: "Vahvista jakaminen",
            .share: "Jaa",
            .cancel: "Peruuta",
            .verifierProve: "%1$s pyytää sinua todistamaan:",
            .verifierShare: "%1$s pyytää sinua jakamaan:",
            .ageBetween: "Olet syntynyt %1$s ja %2$s välisenä aikana (noin %3$d–%4$d-vuotias). Tarkkaa syntymäaikaasi ei jaeta.",
            .ageAtLeast: "Olet vähintään %1$d vuotta vanha. Tarkkaa syntymäaikaasi ei jaeta.",
            .ageAtMost: "Olet enintään %1$d vuotta vanha. Tarkkaa syntymäaikaasi ei jaeta.",
            .pseudonymIssuer: "Palvelulle %1$s jaetaan pseudonyymi. Saat saman pseudonyymin aina, kun käytät tätä palvelua, ja eri pseudonyymin jokaisessa muussa palvelussa. Todistuksesi myöntänyt palvelu voi selvittää, kenelle pseudonyymi kuuluu.",
            .pseudonym: "Palvelulle %1$s jaetaan pseudonyymi. Saat saman pseudonyymin aina, kun käytät tätä palvelua, ja eri pseudonyymin jokaisessa muussa palvelussa.",
            .footer: "Muita henkilötietoja ei jaeta.",
            .claim: "Todistuksesi tieto ”%1$s” jaetaan.",
            .legacyPseudonym: "Pseudonyymi jaetaan palvelulle %1$s.",
            .refusedConsentUnavailable: "Lompakkosi ei voi tällä hetkellä pyytää hyväksyntääsi, joten mitään ei jaettu.",
            .refusedUserDeclined: "Et hyväksynyt pyyntöä, joten mitään ei jaettu.",
            .predicateEq: "%1$s on %2$s.",
            .predicateNe: "%1$s ei ole %2$s.",
            .predicateLt: "%1$s on pienempi kuin %2$s.",
            .predicateLe: "%1$s on enintään %2$s.",
            .predicateGt: "%1$s on suurempi kuin %2$s.",
            .predicateGe: "%1$s on vähintään %2$s.",
            .predicateIn: "%1$s on jokin seuraavista: %2$s.",
            .predicateDateEq: "%1$s on %2$s.",
            .predicateDateNe: "%1$s ei ole %2$s.",
            .predicateDateLt: "%1$s on ennen %2$s.",
            .predicateDateLe: "%1$s on %2$s tai sitä ennen.",
            .predicateDateGt: "%1$s on %2$s jälkeen.",
            .predicateDateGe: "%1$s on %2$s tai sen jälkeen.",
            .predicateDateIn: "%1$s on jokin seuraavista päivämääristä: %2$s.",
        ],
        "el": [
            .title: "Επιβεβαίωση κοινοποίησης",
            .share: "Κοινοποίηση",
            .cancel: "Ακύρωση",
            .verifierProve: "Η υπηρεσία %1$s σας ζητά να αποδείξετε:",
            .verifierShare: "Η υπηρεσία %1$s σας ζητά να κοινοποιήσετε:",
            .ageBetween: "Έχετε γεννηθεί μεταξύ %1$s και %2$s (περίπου %3$d–%4$d ετών). Η ακριβής ημερομηνία γέννησής σας δεν κοινοποιείται.",
            .ageAtLeast: "Είστε τουλάχιστον %1$d ετών. Η ακριβής ημερομηνία γέννησής σας δεν κοινοποιείται.",
            .ageAtMost: "Είστε το πολύ %1$d ετών. Η ακριβής ημερομηνία γέννησής σας δεν κοινοποιείται.",
            .pseudonymIssuer: "Κοινοποιείται ένα ψευδώνυμο για την υπηρεσία %1$s. Λαμβάνετε το ίδιο ψευδώνυμο κάθε φορά που επισκέπτεστε αυτή την υπηρεσία και διαφορετικό σε κάθε άλλη υπηρεσία. Ο φορέας που εξέδωσε το διαπιστευτήριό σας μπορεί να βρει σε ποιον ανήκει αυτό το ψευδώνυμο.",
            .pseudonym: "Κοινοποιείται ένα ψευδώνυμο για την υπηρεσία %1$s. Λαμβάνετε το ίδιο ψευδώνυμο κάθε φορά που επισκέπτεστε αυτή την υπηρεσία και διαφορετικό σε κάθε άλλη υπηρεσία.",
            .footer: "Δεν κοινοποιούνται άλλα προσωπικά δεδομένα.",
            .claim: "Η τιμή «%1$s» από το διαπιστευτήριό σας κοινοποιείται.",
            .legacyPseudonym: "Κοινοποιείται ένα ψευδώνυμο στην υπηρεσία %1$s.",
            .refusedConsentUnavailable: "Το πορτοφόλι σας δεν μπορεί να ζητήσει την έγκρισή σας αυτή τη στιγμή, οπότε δεν κοινοποιήθηκε τίποτα.",
            .refusedUserDeclined: "Δεν εγκρίνατε το αίτημα, οπότε δεν κοινοποιήθηκε τίποτα.",
            .predicateEq: "Το «%1$s» είναι %2$s.",
            .predicateNe: "Το «%1$s» δεν είναι %2$s.",
            .predicateLt: "Το «%1$s» είναι μικρότερο από %2$s.",
            .predicateLe: "Το «%1$s» είναι το πολύ %2$s.",
            .predicateGt: "Το «%1$s» είναι μεγαλύτερο από %2$s.",
            .predicateGe: "Το «%1$s» είναι τουλάχιστον %2$s.",
            .predicateIn: "Το «%1$s» είναι ένα από: %2$s.",
            .predicateDateEq: "Το «%1$s» είναι στις %2$s.",
            .predicateDateNe: "Το «%1$s» δεν είναι στις %2$s.",
            .predicateDateLt: "Το «%1$s» είναι πριν από τις %2$s.",
            .predicateDateLe: "Το «%1$s» είναι στις %2$s ή νωρίτερα.",
            .predicateDateGt: "Το «%1$s» είναι μετά τις %2$s.",
            .predicateDateGe: "Το «%1$s» είναι στις %2$s ή αργότερα.",
            .predicateDateIn: "Το «%1$s» είναι μία από τις ημερομηνίες: %2$s.",
        ],
        "pt": [
            .title: "Confirmar partilha",
            .share: "Partilhar",
            .cancel: "Cancelar",
            .verifierProve: "%1$s pede-lhe que prove:",
            .verifierShare: "%1$s pede-lhe que partilhe:",
            .ageBetween: "Nasceu entre %1$s e %2$s (cerca de %3$d–%4$d anos). A sua data de nascimento exata não é partilhada.",
            .ageAtLeast: "Tem pelo menos %1$d anos. A sua data de nascimento exata não é partilhada.",
            .ageAtMost: "Tem no máximo %1$d anos. A sua data de nascimento exata não é partilhada.",
            .pseudonymIssuer: "É partilhado um pseudónimo para %1$s. Obtém o mesmo pseudónimo sempre que visita este serviço e um diferente em cada outro serviço. O serviço que emitiu a sua credencial consegue apurar a quem pertence este pseudónimo.",
            .pseudonym: "É partilhado um pseudónimo para %1$s. Obtém o mesmo pseudónimo sempre que visita este serviço e um diferente em cada outro serviço.",
            .footer: "Não são partilhados outros dados pessoais.",
            .claim: "O valor de «%1$s» da sua credencial é partilhado.",
            .legacyPseudonym: "É partilhado um pseudónimo com %1$s.",
            .refusedConsentUnavailable: "A sua carteira não consegue pedir a sua aprovação neste momento, por isso nada foi partilhado.",
            .refusedUserDeclined: "Não aprovou o pedido, por isso nada foi partilhado.",
            .predicateEq: "%1$s é %2$s.",
            .predicateNe: "%1$s não é %2$s.",
            .predicateLt: "%1$s é inferior a %2$s.",
            .predicateLe: "%1$s é no máximo %2$s.",
            .predicateGt: "%1$s é superior a %2$s.",
            .predicateGe: "%1$s é pelo menos %2$s.",
            .predicateIn: "%1$s é um de: %2$s.",
            .predicateDateEq: "%1$s é %2$s.",
            .predicateDateNe: "%1$s não é %2$s.",
            .predicateDateLt: "%1$s é anterior a %2$s.",
            .predicateDateLe: "%1$s é %2$s ou anterior.",
            .predicateDateGt: "%1$s é posterior a %2$s.",
            .predicateDateGe: "%1$s é %2$s ou posterior.",
            .predicateDateIn: "%1$s é uma das datas: %2$s.",
        ],
    ]
}
