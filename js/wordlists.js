// Word lists for passphrases and pattern tokens (w / W).
// Lists are de-duplicated at load time, so entropy is computed from the real size.
window.DP_WORDS = (() => {
  const common = `
    able acid aged also area army away baby back ball band bank base bath bear beat bell belt bend best bird
    blow blue boat body bold bolt bone book boot born boss bowl bulk burn bush busy cafe cake calm camp card
    care cart case cash cast cell chat chip city clay clip club coal coat code coin cold cook cool cope copy
    cord core corn cost crew crop cube cure dark data dawn deal dear deck deep deer desk dial dice diet dish
    disk dock door dose down draw drop drum dual duck dust duty earn east easy edge echo epic even exit face
    fact fair fall farm fast fern file film find fine fire firm fish flag flat flow foam fold folk font food
    foot fork form fort four free frog fuel full fund gain game gate gear gift glad glow goal gold golf good
    grab gray grid grin grip grow gulf hair half hall hand harp hawk head heat herb hero hide high hill hint
    hold hole home hood hook hope horn host hour huge hunt idea inch iron isle item jade jazz join joke jump
    jury keen kelp kick kind king kite knee knot lace lake lamp land lane last lava lawn lead leaf lens life
    lift lily lime line lion list load loaf lock loft logo long loop loud luck lung mail main malt mane mark
    mask mast meal melt menu mesh mild milk mill mind mint mist mode mole moon moss moth mule myth nail name
    navy near neck nest news next nice node noon nose note oval oven pace pack page palm park part path peak
    pear pine pink pipe plan plot plum poem poet pond pool port pose post pour pump pure quiz race raft rail
    rain ramp rank rare reef rich ride ring rise road rock roof room root rope rose ruby rule rush rust safe
    sage sail salt sand scan seal seed ship shoe shop silk sing site size skip slab sled slim slot snow soap
    sock sofa soil song soup spin spot star stem step stew suit swan swim tail tale tank tape task team tent
    term test text tide tile time tiny toad tone tool tour town trap tree trim trip tube tuna tune turn twin
    type unit vase vast verb vest view vine visa void vote wade wage walk wall wand warm wave weld well west
    whip wide wild wind wine wing wire wise wolf wood wool word work yard yarn year yoga zero zinc zone
    acorn actor admit adult agent alarm album alien alley amber angle ankle apple arena armor arrow aspen
    atlas audio award bacon badge baker basin batch beach bench berry bison blade blank blaze bloom board
    brave bread brick brook brush cabin cable camel candy canoe cargo cedar chair chalk charm chess chief
    cider cliff clock cloud coach coral couch crane crate crown curve daisy dance delta denim diary diner
    ditch dough drift eagle earth easel elbow ember entry fable fairy feast fence ferry field flame flask
    fleet flint flute focus forge frost fruit gecko ghost giant glass globe grain grape grass gravy guard
    guide habit hazel heart hedge honey horse hotel image inlet ivory jelly jewel judge juice kayak koala
    label laser lemon lever light llama lodge lunar magic mango manor maple medal melon metal mirth model
    money motor mound mouse music noble north novel ocean olive opera orbit otter owner panda panel paper
    party pasta patch pearl pedal penny piano pilot pixel pizza plane plant plaza polar pouch power prism
    quail queen quest quilt radar radio raven razor relic ridge river robin rover royal salad scarf scout
    shade shark shelf shell shore sigil skate slate smoke snake solar spark spice spire spoon squad stack
    staff stage steam steel stone storm stove sugar sunny swamp sword table tango tiger toast topaz torch
    tower track trail train tulip ultra umbra uncle unity vapor vault venom video vigor viper vivid voice
    waltz watch water whale wheat wheel world yacht yeast zebra anchor autumn banjo basket beetle blanket
    bottle bridge bubble button candle canyon carpet castle cheese cherry circle cobweb copper cotton
    cradle dinner donkey dragonfly engine fabric falcon feather finger flower forest garden ginger guitar
    hammer harbor helmet island jacket jungle kettle ladder lagoon lizard locket magnet marble meadow
    mirror monkey napkin needle nickel oyster paddle parrot pebble pepper pickle pillow planet pocket
    puzzle rabbit ribbon rocket saddle salmon silver sketch spider spirit spring statue summer sunset
    tablet teapot temple thread ticket timber tomato tunnel turtle velvet violin walrus window winter wizard
  `;

  const fantasy = `
    aether alchemy amulet ancient anvil arcane ashen azure bane banner bard basilisk beacon blight
    bloodstone brimstone bulwark cairn caldera cauldron cavern chalice charred chimera cinder citadel
    cleric cloak cobalt crag crimson crypt crystal dagger dire dragon drake dread druid dungeon dusk
    eclipse eldritch elixir elven emberfall emerald enchant fang fiend firebrand flagon forsaken fortress
    gargoyle garnet gauntlet gilded glade glyph goblet golem gorge griffin grimoire grotto halberd hallow
    harbinger helm herald hoard hollow howl hydra inferno jasper keep kindle kraken labyrinth lance lantern
    legend lich lore magma manticore mantle mead mithril molten monolith moonstone mystic nether nomad
    obsidian omen onyx oracle paladin parchment phoenix pike potion pyre quarry quiver rampart ranger
    realm reaver rift rogue ruin rune sable sapphire scale scepter scorch scroll sentinel serpent shadow
    shard shield shrine siege smolder sorcery specter spell sphinx squire steed summit talon tempest
    thorn throne thunder tome torment totem troll tundra twilight valor vanguard vellum vigil warden
    warlock wyrm wyvern zealot zephyr basalt behemoth bonfire brazier coven direwolf emberheart fireborn
    gloom hearth ignite incant kingdom knight lair marauder myrrh nightfall oath plunder scorn scythe
    sorcerer sunfire tinder valkyrie vortex warhorn wildfire ashfall bastion blackfire bloodmoon bramble
    broadsword catacomb cindervale cragmaw darkling dawnstar deepfire dirge dreadfang duskwing embers
    enchanter everflame fellwind firestorm flamecrest frostfang gemstone ghoul goblin gravecall
    hellfire highborn hollowmere ironclad ironscale kinslayer longbow magefire mistral moonfire
    nightshade nightwing oathbound oldgod onslaught pyrelight ravenhold redscale rimefire runeblade
    runestone sandstorm scalebound shadowfen shieldwall skyfire smokewing soulfire spellbook starfall
    stormcrow sunspear thornwood thunderhoof truesilver vampire venomous warband warbringer wraith
  `;

  const split = s => [...new Set(s.trim().split(/\s+/))];
  const lists = { common: split(common), fantasy: split(fantasy) };
  lists.both = [...new Set([...lists.common, ...lists.fantasy])];
  return lists;
})();

// Frequently used passwords, checked by the strength tester.
window.DP_COMMON_PASSWORDS = new Set(`
  password password1 123456 12345678 123456789 1234567890 12345 1234567 qwerty qwerty123 qwertyuiop
  abc123 111111 000000 123123 letmein welcome monkey dragon master sunshine princess football baseball
  shadow superman batman trustno1 iloveyou admin admin123 login passw0rd p@ssw0rd p@ssword starwars
  hello freedom whatever charlie donald michael jennifer jordan hunter ranger buster soccer harley
  hockey killer george thomas pepper summer winter flower cookie ginger cheese computer internet
  secret changeme default guest root toor test test123 asdf asdfgh asdfghjkl zxcvbnm 1q2w3e4r 1qaz2wsx
  666666 696969 121212 7777777 654321 987654321 mustang access maggie liverpool chelsea arsenal
`.trim().split(/\s+/));
