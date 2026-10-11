"""
ScamShield AI — Telegram Web Security Engine & Crypto Defense (/a/ & /k/)
Covers:
1. Crypto task fraud, VIP airdrops, double-your-crypto, guaranteed daily ROI, USDT task/like-and-earn.
2. Wallet drainers, wallet-connect phishing, seed phrase defense (BIP39 subset, ≥8 consecutive words), private keys.
3. Indian currency reward scams: UPI/INR lottery/prize lures (₹/Rs., KBC lottery, PM scheme, Hinglish phrasing).
4. Fake admin/support DMs, fake channel verification, impersonation.
"""
from __future__ import annotations
import re

# Small embedded BIP39 English wordlist subset for seed phrase harvesting detection
BIP39_SUBSET = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
    "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
    "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
    "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
    "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
    "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
    "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
    "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
    "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud",
    "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "coin", "collect", "color", "column", "combine", "come", "comfort", "comic",
    "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider",
    "control", "convince", "cook", "cool", "copper", "copy", "coral", "core",
    "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course",
    "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane",
    "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew",
    "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd",
    "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal",
    "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve",
    "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance",
    "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate",
    "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer",
    "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise",
    "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy",
    "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail",
    "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary",
    "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner",
    "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss",
    "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor",
    "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor",
    "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic",
    "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive",
    "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust",
    "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn",
    "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge",
    "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder",
    "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark",
    "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable",
    "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage",
    "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure",
    "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era",
    "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence",
    "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact",
    "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise",
    "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect",
    "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow",
    "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false",
    "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion",
    "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february",
    "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch",
    "fever", "few", "fiber", "fiction", "field", "figure", "file", "film",
    "filter", "final", "find", "fine", "finger", "finish", "fire", "firm",
    "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame",
    "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock",
    "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog",
    "foil", "fold", "follow", "food", "foot", "force", "forest", "forget",
    "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox",
    "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front",
    "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace",
    "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap",
    "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate",
    "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine",
    "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl",
    "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe",
    "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold",
    "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab",
    "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green",
    "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard",
    "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair",
    "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh",
    "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart",
    "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero",
    "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby",
    "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood",
    "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour",
    "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon",
    "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image",
    "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch",
    "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant",
    "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate",
    "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire",
    "install", "intact", "interest", "into", "invest", "invite", "involve", "iron",
    "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar",
    "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke",
    "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk",
    "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid",
    "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten",
    "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor",
    "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later",
    "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer",
    "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg",
    "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard",
    "lesson", "letter", "level", "liar", "liberty", "library", "license", "life",
    "lift", "light", "like", "limb", "limit", "link", "lion", "liquid",
    "list", "little", "live", "lizard", "load", "loan", "lobster", "local",
    "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge",
    "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury",
    "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main",
    "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion",
    "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage",
    "mask", "mass", "master", "match", "material", "math", "matrix", "matter",
    "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal",
    "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy",
    "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle",
    "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute",
    "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture",
    "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster",
    "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion",
    "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule",
    "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself",
    "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation",
    "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew",
    "nerve", "nest", "net", "network", "neutral", "never", "news", "next",
    "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north",
    "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear",
    "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure",
    "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off",
    "offer", "office", "often", "oil", "okay", "old", "olive", "olympic",
    "omit", "once", "one", "onion", "online", "only", "open", "opera",
    "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary",
    "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer",
    "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen",
    "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm",
    "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park",
    "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern",
    "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican",
    "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person",
    "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture",
    "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe",
    "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play",
    "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point",
    "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion",
    "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power",
    "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent",
    "price", "pride", "primary", "print", "priority", "prison", "private", "prize",
    "problem", "process", "produce", "profit", "program", "project", "promote", "proof",
    "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull",
    "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity",
    "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum",
    "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon",
    "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally",
    "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather",
    "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild",
    "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform",
    "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief",
    "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent",
    "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble",
    "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion",
    "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich",
    "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple",
    "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust",
    "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough",
    "round", "route", "royal", "rubber", "rude", "rug", "rule", "run",
    "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad",
    "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy",
    "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare",
    "scatter", "scene", "scheme", "school", "science", "scissors", "scooter", "scope",
    "scorch", "score", "scout", "scrap", "screen", "script", "scrub", "sea",
    "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
    "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
    "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
    "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
    "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
    "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
    "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
    "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
    "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
    "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
    "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
    "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
    "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
    "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
    "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
    "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
    "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
    "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
    "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
    "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
    "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
    "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
    "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
    "theme", "then", "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger",
    "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
    "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
    "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
    "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
    "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
    "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
    "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
    "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
    "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
    "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
    "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon",
    "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
    "useless", "usual", "utility", "vacant", "vacuum", "vague", "valuable", "valve",
    "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet",
    "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel",
    "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village",
    "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital",
    "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage",
    "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "war",
    "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
    "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend",
    "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel",
    "when", "where", "whip", "whisper", "wide", "width", "wife", "wild",
    "will", "win", "window", "wine", "wing", "wink", "winner", "winter",
    "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder",
    "wood", "wool", "word", "work", "world", "worry", "worth", "wrap",
    "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow",
    "you", "young", "youth", "zebra", "zero", "zone", "zoo"
}

# Regex for consecutive bip39 words detection (flags ≥8 consecutive BIP39 words)
def detect_consecutive_seed_words(text: str, min_words: int = 8) -> bool:
    """Flags sequences of >= 8 consecutive BIP39 dictionary words."""
    words = re.findall(r"\b[a-zA-Z]{3,8}\b", text.lower())
    consecutive = 0
    for w in words:
        if w in BIP39_SUBSET:
            consecutive += 1
            if consecutive >= min_words:
                return True
        else:
            consecutive = 0
    return False


# Regex patterns for Telegram Threats
RE_TELEGRAM_CRYPTO_LURES = re.compile(
    r"(double\s+your\s+(crypto|btc|eth|usdt|coins?)|"
    r"guaranteed\s+(\d+%\s+)?(daily\s+|weekly\s+)?(roi|return|profit)|"
    r"vip\s+(airdrop|signals?|trading|pump)|"
    r"pump\s+signals?|free\s+(usdt|tokens?|coins?|eth|btc)|"
    r"(usdt|crypto)\s+task|like\s+and\s+earn\s*(task|job)?|"
    r"join\s+.{0,25}(signals?|pump|vip)\s+(group|channel)|"
    r"100x\s+guaranteed|passive\s+income\s+.{0,15}crypto|"
    r"send\s+\d+\s*(eth|btc|sol)\s+and\s+get\s+\d+)",
    re.I
)

RE_TELEGRAM_WALLET_DRAINER = re.compile(
    r"(enter\s+.{0,15}(seed|recovery|mnemonic)\s+phrase|"
    r"validate\s+.{0,15}wallet|claim\s+.{0,15}(airdrop|tokens?)\s+.{0,15}wallet|"
    r"connect\s+.{0,15}wallet\s+.{0,15}(claim|verify|sync)|"
    r"(sync|rectify|update)\s+.{0,15}wallet|"
    r"private\s+key|"
    r"(12|24)\s*-?\s*words?\s*(seed|recovery|mnemonic|key)|"
    r"wallet[\s-]?connect\s+.{0,20}(verify|claim|sync|validate)|"
    r"dapp\s+.{0,15}(claim|drain|sync))",
    re.I
)

RE_TELEGRAM_INR_LURES = re.compile(
    r"(₹\s*\d[\d,]*\s*(reward|won|prize|cashback|pending|bonus|claim)|"
    r"rs\.?\s*\d[\d,]*\s*(reward|won|prize|cashback|pending|bonus|claim)|"
    r"inr\s+\d[\d,]*\s*(reward|won|credit|cashback)|"
    r"(kbc|kaun\s+banega\s+crorepati)\s+(lottery|winner|prize|lucky)|"
    r"(pm|modi|pradhan\s+mantri)\s+(scheme|yojana|fund)\s+.{0,20}(reward|claim|giveaway)|"
    r"claim\s+.{0,20}(reward|prize|cashback)\s+.{0,15}(on\s+)?(upi|gpay|phonepe|paytm|bhim)|"
    r"apko\s+\d+\s*(rupaye|rs|inr|cashback)\s+mila\s+hai|"
    r"paise\s+claim\s+karo|lottery\s+lagi\s+hai)",
    re.I
)

RE_TELEGRAM_IMPERSONATION = re.compile(
    r"(telegram\s+(admin|support|team|official|security)|"
    r"channel\s+verification|verify\s+.{0,10}channel|"
    r"your\s+(account|channel)\s+.{0,20}(restrict|ban|suspend|delet|violat)|"
    r"official\s+helpdesk)",
    re.I
)


def analyze_telegram_threats(text: str) -> dict:
    """
    Analyzes Telegram message text specifically for crypto lures, wallet drainers,
    seed phrase harvesting, and Indian currency reward lures.
    Returns: {
        detected: bool,
        scam_dna: list[str],
        evidence: list[str],
        recommendations: list[str],
        score_boost: int,
        category: str
    }
    """
    dna = []
    evidence = []
    recs = []
    score_boost = 0
    category = "Conversations"

    # 1. Seed phrase harvesting & consecutive wordlist check
    if RE_TELEGRAM_WALLET_DRAINER.search(text):
        dna.append("Seed Phrase Harvest")
        dna.append("Wallet Drainer")
        evidence.append("Explicit request for wallet seed phrase or private key validation")
        recs.append("Never enter your 12 or 24-word seed phrase anywhere online")
        recs.append("No legitimate crypto support will ever ask for your private key")
        score_boost += 85
        category = "Seed Phrase Harvest"

    elif detect_consecutive_seed_words(text, min_words=8):
        dna.append("Seed Phrase Harvest")
        dna.append("Wallet Drainer")
        evidence.append("Detected 8+ consecutive BIP39 mnemonic dictionary words")
        recs.append("Detected mnemonic seed phrase in text — do NOT share or publish this")
        score_boost += 80
        category = "Seed Phrase Harvest"

    # 2. Crypto tasks / Airdrop / Guaranteed ROI
    if RE_TELEGRAM_CRYPTO_LURES.search(text):
        dna.append("Crypto Lure")
        if "airdrop" in text.lower() or "usdt task" in text.lower() or "like and earn" in text.lower():
            dna.append("Wallet Drainer")
        evidence.append("Unrealistic guaranteed returns or cryptocurrency airdrop lure detected")
        recs.append("Cryptocurrency yields with 'guaranteed ROI' are fraudulent Ponzi schemes")
        recs.append("Never authorize token approvals on untrusted Web3 dApps")
        score_boost += 60
        if not category or category == "Conversations":
            category = "Crypto Lure"

    # 3. INR / UPI Lottery & Reward Scams
    if RE_TELEGRAM_INR_LURES.search(text):
        dna.append("INR Reward Lure")
        dna.append("Payment Pivot")
        evidence.append("Indian currency (₹/Rs.) prize lure with UPI redirection pattern")
        recs.append("Legitimate lotteries and government schemes do not distribute rewards over Telegram or UPI")
        recs.append("Entering your UPI PIN is solely for paying money, NEVER for receiving money")
        score_boost += 65
        if not category or category == "Conversations":
            category = "INR Reward Lure"

    # 4. Fake Telegram Admin / Channel Impersonation
    if RE_TELEGRAM_IMPERSONATION.search(text):
        dna.append("Urgency Pressure")
        evidence.append("Fake Telegram admin impersonation claiming pending restriction")
        recs.append("Official Telegram staff never message via regular direct messages")
        score_boost += 50

    return {
        "detected": len(dna) > 0,
        "scam_dna": list(dict.fromkeys(dna)),
        "evidence": evidence,
        "recommendations": list(dict.fromkeys(recs)),
        "score_boost": score_boost,
        "category": category,
    }
