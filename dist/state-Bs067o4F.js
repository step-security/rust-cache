import require$$0 from 'net';
import require$$1 from 'tls';
import assert from 'assert';
import { r as requireSrc } from './index-7LN3rhJP.js';
import require$$2 from 'url';
import require$$0__default from 'events';
import http__default from 'http';
import https__default from 'https';

var balancedMatch;
var hasRequiredBalancedMatch;

function requireBalancedMatch () {
	if (hasRequiredBalancedMatch) return balancedMatch;
	hasRequiredBalancedMatch = 1;
	balancedMatch = balanced;
	function balanced(a, b, str) {
	  if (a instanceof RegExp) a = maybeMatch(a, str);
	  if (b instanceof RegExp) b = maybeMatch(b, str);

	  var r = range(a, b, str);

	  return r && {
	    start: r[0],
	    end: r[1],
	    pre: str.slice(0, r[0]),
	    body: str.slice(r[0] + a.length, r[1]),
	    post: str.slice(r[1] + b.length)
	  };
	}

	function maybeMatch(reg, str) {
	  var m = str.match(reg);
	  return m ? m[0] : null;
	}

	balanced.range = range;
	function range(a, b, str) {
	  var begs, beg, left, right, result;
	  var ai = str.indexOf(a);
	  var bi = str.indexOf(b, ai + 1);
	  var i = ai;

	  if (ai >= 0 && bi > 0) {
	    if(a===b) {
	      return [ai, bi];
	    }
	    begs = [];
	    left = str.length;

	    while (i >= 0 && !result) {
	      if (i == ai) {
	        begs.push(i);
	        ai = str.indexOf(a, i + 1);
	      } else if (begs.length == 1) {
	        result = [ begs.pop(), bi ];
	      } else {
	        beg = begs.pop();
	        if (beg < left) {
	          left = beg;
	          right = bi;
	        }

	        bi = str.indexOf(b, i + 1);
	      }

	      i = ai < bi && ai >= 0 ? ai : bi;
	    }

	    if (begs.length) {
	      result = [ left, right ];
	    }
	  }

	  return result;
	}
	return balancedMatch;
}

var braceExpansion;
var hasRequiredBraceExpansion;

function requireBraceExpansion () {
	if (hasRequiredBraceExpansion) return braceExpansion;
	hasRequiredBraceExpansion = 1;
	var balanced = requireBalancedMatch();

	braceExpansion = expandTop;

	var escSlash = '\0SLASH'+Math.random()+'\0';
	var escOpen = '\0OPEN'+Math.random()+'\0';
	var escClose = '\0CLOSE'+Math.random()+'\0';
	var escComma = '\0COMMA'+Math.random()+'\0';
	var escPeriod = '\0PERIOD'+Math.random()+'\0';

	var EXPANSION_MAX = 100000;

	// `EXPANSION_MAX` caps the *number* of expansions, but not their length. An
	// input like `'{a,b}'.repeat(1500)` stays under that count - its output is
	// truncated to 100k results - while making every result ~1500 characters
	// long. The result set, and the intermediate arrays built while combining
	// brace sets, then grow large enough to exhaust memory and crash the process
	// (CVE-2026-14257). `EXPANSION_MAX_LENGTH` bounds the total number of
	// characters the accumulator may hold at any point, so memory stays flat no
	// matter how many brace groups are chained. The limit sits well above any
	// realistic expansion (100k results hitting `EXPANSION_MAX` measure ~1M
	// characters) so legitimate input is unaffected.
	var EXPANSION_MAX_LENGTH = 4000000;

	function numeric(str) {
	  return parseInt(str, 10) == str
	    ? parseInt(str, 10)
	    : str.charCodeAt(0);
	}

	function escapeBraces(str) {
	  return str.split('\\\\').join(escSlash)
	            .split('\\{').join(escOpen)
	            .split('\\}').join(escClose)
	            .split('\\,').join(escComma)
	            .split('\\.').join(escPeriod);
	}

	function unescapeBraces(str) {
	  return str.split(escSlash).join('\\')
	            .split(escOpen).join('{')
	            .split(escClose).join('}')
	            .split(escComma).join(',')
	            .split(escPeriod).join('.');
	}


	// Basically just str.split(","), but handling cases
	// where we have nested braced sections, which should be
	// treated as individual members, like {a,{b,c},d}
	function parseCommaParts(str) {
	  if (!str)
	    return [''];

	  var parts = [];
	  var m = balanced('{', '}', str);

	  if (!m)
	    return str.split(',');

	  var pre = m.pre;
	  var body = m.body;
	  var post = m.post;
	  var p = pre.split(',');

	  p[p.length-1] += '{' + body + '}';
	  var postParts = parseCommaParts(post);
	  if (post.length) {
	    p[p.length-1] += postParts.shift();
	    p.push.apply(p, postParts);
	  }

	  parts.push.apply(parts, p);

	  return parts;
	}

	function expandTop(str, options) {
	  if (!str)
	    return [];

	  options = options || {};
	  var max = options.max == null ? EXPANSION_MAX : options.max;
	  var maxLength = options.maxLength == null ? EXPANSION_MAX_LENGTH : options.maxLength;

	  // I don't know why Bash 4.3 does this, but it does.
	  // Anything starting with {} will have the first two bytes preserved
	  // but *only* at the top level, so {},a}b will not expand to anything,
	  // but a{},b}c will be expanded to [a}c,abc].
	  // One could argue that this is a bug in Bash, but since the goal of
	  // this module is to match Bash's rules, we escape a leading {}
	  if (str.substr(0, 2) === '{}') {
	    str = '\\{\\}' + str.substr(2);
	  }

	  return expand(escapeBraces(str), max, maxLength, true).map(unescapeBraces);
	}

	function embrace(str) {
	  return '{' + str + '}';
	}
	function isPadded(el) {
	  return /^-?0\d/.test(el);
	}

	function lte(i, y) {
	  return i <= y;
	}
	function gte(i, y) {
	  return i >= y;
	}

	// Build `{ acc[a] + pre + values[v] }` for every combination, capping the
	// number of results at `max` and the total number of characters at `maxLength`.
	// This is the one place output grows, so bounding it here keeps the single
	// accumulator - and therefore memory - flat regardless of how many brace groups
	// are combined (CVE-2026-14257).
	//
	// `base[a]` is the length of the part of `acc[a]` that predates the current
	// empty-drop baseline (see `expand`). The matching baselines for the results
	// are appended to `outBase`, which the caller carries forward alongside them.
	function combine(
	  acc,
	  base,
	  pre,
	  values,
	  max,
	  maxLength,
	  dropEmpties,
	  outBase
	) {
	  var out = [];
	  var length = 0;
	  for (var a = 0; a < acc.length; a++) {
	    for (var v = 0; v < values.length; v++) {
	      if (out.length >= max) return out
	      var expansion = acc[a] + pre + values[v];
	      // Bash drops empty results at the top level. Skip them before they count
	      // against `max`, so `max` bounds the number of *kept* results. "Empty"
	      // means "adds nothing past the baseline", not "empty overall".
	      if (dropEmpties && expansion.length === base[a]) continue
	      if (length + expansion.length > maxLength) return out
	      out.push(expansion);
	      outBase.push(base[a]);
	      length += expansion.length;
	    }
	  }
	  return out
	}

	// The expansion values of a single numeric (`1..5`) or alphabetic (`a..e..2`)
	// sequence body.
	function expandSequence(
	  body,
	  isAlphaSequence,
	  max,
	  maxLength
	) {
	  var n = body.split(/\.\./);
	  var N = [];
	  // A sequence body always splits into two or three parts, but the compiler
	  // can't know that.
	  /* c8 ignore start */
	  if (n[0] === undefined || n[1] === undefined) {
	    return N
	  }
	  /* c8 ignore stop */
	  var x = numeric(n[0]);
	  var y = numeric(n[1]);
	  var width = Math.max(n[0].length, n[1].length);
	  var incr =
	    n.length === 3 && n[2] !== undefined ?
	      Math.max(Math.abs(numeric(n[2])), 1)
	    : 1;
	  var test = lte;
	  var reverse = y < x;
	  if (reverse) {
	    incr *= -1;
	    test = gte;
	  }
	  var pad = n.some(isPadded);

	  var length = 0;
	  for (var i = x; test(i, y) && N.length < max; i += incr) {
	    var c;
	    if (isAlphaSequence) {
	      c = String.fromCharCode(i);
	      if (c === '\\') {
	        c = '';
	      }
	    } else {
	      c = String(i);
	      if (pad) {
	        var need = width - c.length;
	        if (need > 0) {
	          var z = new Array(need + 1).join('0');
	          if (i < 0) {
	            c = '-' + z + c.slice(1);
	          } else {
	            c = z + c;
	          }
	        }
	      }
	    }
	    if (length + c.length > maxLength) break
	    N.push(c);
	    length += c.length;
	  }
	  return N
	}

	function expand(
	  str,
	  max,
	  maxLength,
	  isTop
	) {
	  // Consume the string's top-level brace groups left to right, threading a
	  // running set of combined prefixes (`acc`). Expanding the tail iteratively -
	  // rather than recursing on `m.post` once per group - keeps the native stack
	  // depth constant, so deeply chained input (`'{a,b}'.repeat(3000)`) can no
	  // longer overflow the stack, and leaves a single accumulator whose size
	  // `maxLength` bounds directly (CVE-2026-14257).
	  var acc = [''];

	  // Bash drops empty results, but only when the *first* group of the run is a
	  // comma set - a sequence like `{a..\}` may legitimately yield ''. The drop
	  // is on the final strings, so it is applied to whichever `combine` produces
	  // them (the one with no brace set left in the tail).
	  //
	  // The old implementation recursed on `m.post`, so the drop tested only the
	  // expansion of the current call's substring. The `{a},b}` rewrite below turns
	  // `isTop` back on part-way through a string, starting a fresh such run, so
	  // the drop must ignore whatever `acc` already holds from earlier groups.
	  // `accBase[a]` records how much of `acc[a]` predates the current run;
	  // `combine` treats an expansion as empty when it adds nothing past that.
	  var accBase = [0];
	  var dropEmpties = false;
	  var firstGroup = true;
	  var nextBase;

	  for (;;) {
	    var m = balanced('{', '}', str);

	    // No brace set left: the rest of the string is literal.
	    if (!m) {
	      return combine(acc, accBase, str, [''], max, maxLength, dropEmpties, [])
	    }

	    // no need to expand pre, since it is guaranteed to be free of brace-sets
	    var pre = m.pre;

	    // For compatibility reasons, `${` is not eligible for brace expansion, and
	    // on the 1.x line it suppresses expansion of the rest of the string too:
	    // the whole remainder is literal. The 2.x and 5.x lines instead keep
	    // expanding the tail, which is what bash does, but changing that here would
	    // be a breaking change for 1.x consumers. Routed through `combine` so the
	    // result is still bounded by `max` and `maxLength`.
	    if (/\$$/.test(pre)) {
	      return combine(acc, accBase, str, [''], max, maxLength, dropEmpties, [])
	    }

	    var isNumericSequence = /^-?\d+\.\.-?\d+(?:\.\.-?\d+)?$/.test(m.body);
	    var isAlphaSequence = /^[a-zA-Z]\.\.[a-zA-Z](?:\.\.-?\d+)?$/.test(m.body);
	    var isSequence = isNumericSequence || isAlphaSequence;
	    var isOptions = m.body.indexOf(',') >= 0;
	    if (!isSequence && !isOptions) {
	      // {a},b}
	      if (m.post.match(/,(?!,).*\}/)) {
	        str = m.pre + '{' + m.body + escClose + m.post;
	        // The rewritten string is expanded as if it were a fresh top-level one,
	        // so start a new empty-drop run: anchor the baseline at what `acc`
	        // holds now, and let the next expanding group decide whether to drop.
	        isTop = true;
	        firstGroup = true;
	        dropEmpties = false;
	        accBase = [];
	        for (var b = 0; b < acc.length; b++) {
	          accBase.push(acc[b].length);
	        }
	        continue
	      }
	      // Nothing here expands, so the whole remaining string is literal.
	      return combine(
	        acc,
	        accBase,
	        pre + '{' + m.body + '}' + m.post,
	        [''],
	        max,
	        maxLength,
	        dropEmpties,
	        []
	      )
	    }

	    if (firstGroup) {
	      dropEmpties = isTop && !isSequence;
	      firstGroup = false;
	    }

	    var values;
	    if (isSequence) {
	      values = expandSequence(m.body, isAlphaSequence, max, maxLength);
	    } else {
	      var n = parseCommaParts(m.body);
	      if (n.length === 1 && n[0] !== undefined) {
	        // x{{a,b}}y ==> x{a}y x{b}y
	        n = expand(n[0], max, maxLength, false).map(embrace);
	        //XXX is this necessary? Can't seem to hit it in tests.
	        /* c8 ignore start */
	        if (n.length === 1) {
	          nextBase = [];
	          acc = combine(
	            acc,
	            accBase,
	            pre + n[0],
	            [''],
	            max,
	            maxLength,
	            dropEmpties && !m.post.length,
	            nextBase
	          );
	          accBase = nextBase;
	          if (!m.post.length) break
	          str = m.post;
	          continue
	        }
	        /* c8 ignore stop */
	      }

	      // Values that `combine` is going to drop as empty produce no result, so
	      // they must not count against `max` - otherwise `{a,,b}` with `max: 2`
	      // would stop at `['a', '']` and yield one result instead of two. Skipping
	      // them outright keeps `values` bounded while leaving `max` a bound on
	      // *kept* results. A value is dropped when it adds nothing past the
	      // baseline, which is what `combine` tests.
	      var dropsEmpties = dropEmpties && !m.post.length && !pre;
	      for (var d = 0; dropsEmpties && d < acc.length; d++) {
	        if (acc[d].length !== accBase[d]) {
	          dropsEmpties = false;
	        }
	      }

	      values = [];
	      var valuesLength = 0;
	      outer: for (var j = 0; j < n.length; j++) {
	        var expanded = expand(n[j], max, maxLength, false);
	        for (var k = 0; k < expanded.length; k++) {
	          var v = expanded[k];
	          if (dropsEmpties && !v) continue
	          if (values.length >= max || valuesLength + v.length > maxLength) {
	            break outer
	          }
	          values.push(v);
	          valuesLength += v.length;
	        }
	      }
	    }

	    nextBase = [];
	    acc = combine(
	      acc,
	      accBase,
	      pre,
	      values,
	      max,
	      maxLength,
	      dropEmpties && !m.post.length,
	      nextBase
	    );
	    accBase = nextBase;
	    if (!m.post.length) break
	    str = m.post;
	  }

	  return acc
	}
	return braceExpansion;
}

var minimatch_1;
var hasRequiredMinimatch;

function requireMinimatch () {
	if (hasRequiredMinimatch) return minimatch_1;
	hasRequiredMinimatch = 1;
	minimatch_1 = minimatch;
	minimatch.Minimatch = Minimatch;

	var path = (function () { try { return require('path') } catch (e) {}}()) || {
	  sep: '/'
	};
	minimatch.sep = path.sep;

	var GLOBSTAR = minimatch.GLOBSTAR = Minimatch.GLOBSTAR = {};
	var expand = requireBraceExpansion();

	var plTypes = {
	  '!': { open: '(?:(?!(?:', close: '))[^/]*?)'},
	  '?': { open: '(?:', close: ')?' },
	  '+': { open: '(?:', close: ')+' },
	  '*': { open: '(?:', close: ')*' },
	  '@': { open: '(?:', close: ')' }
	};

	// any single thing other than /
	// don't need to escape / when using new RegExp()
	var qmark = '[^/]';

	// * => any number of characters
	var star = qmark + '*?';

	// ** when dots are allowed.  Anything goes, except .. and .
	// not (^ or / followed by one or two dots followed by $ or /),
	// followed by anything, any number of times.
	var twoStarDot = '(?:(?!(?:\\\/|^)(?:\\.{1,2})($|\\\/)).)*?';

	// not a ^ or / followed by a dot,
	// followed by anything, any number of times.
	var twoStarNoDot = '(?:(?!(?:\\\/|^)\\.).)*?';

	// characters that need to be escaped in RegExp.
	var reSpecials = charSet('().*{}+?[]^$\\!');

	// "abc" -> { a:true, b:true, c:true }
	function charSet (s) {
	  return s.split('').reduce(function (set, c) {
	    set[c] = true;
	    return set
	  }, {})
	}

	// normalizes slashes.
	var slashSplit = /\/+/;

	minimatch.filter = filter;
	function filter (pattern, options) {
	  options = options || {};
	  return function (p, i, list) {
	    return minimatch(p, pattern, options)
	  }
	}

	function ext (a, b) {
	  b = b || {};
	  var t = {};
	  Object.keys(a).forEach(function (k) {
	    t[k] = a[k];
	  });
	  Object.keys(b).forEach(function (k) {
	    t[k] = b[k];
	  });
	  return t
	}

	minimatch.defaults = function (def) {
	  if (!def || typeof def !== 'object' || !Object.keys(def).length) {
	    return minimatch
	  }

	  var orig = minimatch;

	  var m = function minimatch (p, pattern, options) {
	    return orig(p, pattern, ext(def, options))
	  };

	  m.Minimatch = function Minimatch (pattern, options) {
	    return new orig.Minimatch(pattern, ext(def, options))
	  };
	  m.Minimatch.defaults = function defaults (options) {
	    return orig.defaults(ext(def, options)).Minimatch
	  };

	  m.filter = function filter (pattern, options) {
	    return orig.filter(pattern, ext(def, options))
	  };

	  m.defaults = function defaults (options) {
	    return orig.defaults(ext(def, options))
	  };

	  m.makeRe = function makeRe (pattern, options) {
	    return orig.makeRe(pattern, ext(def, options))
	  };

	  m.braceExpand = function braceExpand (pattern, options) {
	    return orig.braceExpand(pattern, ext(def, options))
	  };

	  m.match = function (list, pattern, options) {
	    return orig.match(list, pattern, ext(def, options))
	  };

	  return m
	};

	Minimatch.defaults = function (def) {
	  return minimatch.defaults(def).Minimatch
	};

	function minimatch (p, pattern, options) {
	  assertValidPattern(pattern);

	  if (!options) options = {};

	  // shortcut: comments match nothing.
	  if (!options.nocomment && pattern.charAt(0) === '#') {
	    return false
	  }

	  return new Minimatch(pattern, options).match(p)
	}

	function Minimatch (pattern, options) {
	  if (!(this instanceof Minimatch)) {
	    return new Minimatch(pattern, options)
	  }

	  assertValidPattern(pattern);

	  if (!options) options = {};

	  pattern = pattern.trim();

	  // windows support: need to use /, not \
	  if (!options.allowWindowsEscape && path.sep !== '/') {
	    pattern = pattern.split(path.sep).join('/');
	  }

	  this.options = options;
	  this.maxGlobstarRecursion = options.maxGlobstarRecursion !== undefined
	    ? options.maxGlobstarRecursion : 200;
	  this.set = [];
	  this.pattern = pattern;
	  this.regexp = null;
	  this.negate = false;
	  this.comment = false;
	  this.empty = false;
	  this.partial = !!options.partial;

	  // make the set of regexps etc.
	  this.make();
	}

	Minimatch.prototype.debug = function () {};

	Minimatch.prototype.make = make;
	function make () {
	  var pattern = this.pattern;
	  var options = this.options;

	  // empty patterns and comments match nothing.
	  if (!options.nocomment && pattern.charAt(0) === '#') {
	    this.comment = true;
	    return
	  }
	  if (!pattern) {
	    this.empty = true;
	    return
	  }

	  // step 1: figure out negation, etc.
	  this.parseNegate();

	  // step 2: expand braces
	  var set = this.globSet = this.braceExpand();

	  if (options.debug) this.debug = function debug() { console.error.apply(console, arguments); };

	  this.debug(this.pattern, set);

	  // step 3: now we have a set, so turn each one into a series of path-portion
	  // matching patterns.
	  // These will be regexps, except in the case of "**", which is
	  // set to the GLOBSTAR object for globstar behavior,
	  // and will not contain any / characters
	  set = this.globParts = set.map(function (s) {
	    return s.split(slashSplit)
	  });

	  this.debug(this.pattern, set);

	  // glob --> regexps
	  set = set.map(function (s, si, set) {
	    return s.map(this.parse, this)
	  }, this);

	  this.debug(this.pattern, set);

	  // filter out everything that didn't compile properly.
	  set = set.filter(function (s) {
	    return s.indexOf(false) === -1
	  });

	  this.debug(this.pattern, set);

	  this.set = set;
	}

	Minimatch.prototype.parseNegate = parseNegate;
	function parseNegate () {
	  var pattern = this.pattern;
	  var negate = false;
	  var options = this.options;
	  var negateOffset = 0;

	  if (options.nonegate) return

	  for (var i = 0, l = pattern.length
	    ; i < l && pattern.charAt(i) === '!'
	    ; i++) {
	    negate = !negate;
	    negateOffset++;
	  }

	  if (negateOffset) this.pattern = pattern.substr(negateOffset);
	  this.negate = negate;
	}

	// Brace expansion:
	// a{b,c}d -> abd acd
	// a{b,}c -> abc ac
	// a{0..3}d -> a0d a1d a2d a3d
	// a{b,c{d,e}f}g -> abg acdfg acefg
	// a{b,c}d{e,f}g -> abdeg acdeg abdeg abdfg
	//
	// Invalid sets are not expanded.
	// a{2..}b -> a{2..}b
	// a{b}c -> a{b}c
	minimatch.braceExpand = function (pattern, options) {
	  return braceExpand(pattern, options)
	};

	Minimatch.prototype.braceExpand = braceExpand;

	function braceExpand (pattern, options) {
	  if (!options) {
	    if (this instanceof Minimatch) {
	      options = this.options;
	    } else {
	      options = {};
	    }
	  }

	  pattern = typeof pattern === 'undefined'
	    ? this.pattern : pattern;

	  assertValidPattern(pattern);

	  // Thanks to Yeting Li <https://github.com/yetingli> for
	  // improving this regexp to avoid a ReDOS vulnerability.
	  if (options.nobrace || !/\{(?:(?!\{).)*\}/.test(pattern)) {
	    // shortcut. no need to expand.
	    return [pattern]
	  }

	  return expand(pattern)
	}

	var MAX_PATTERN_LENGTH = 1024 * 64;
	var assertValidPattern = function (pattern) {
	  if (typeof pattern !== 'string') {
	    throw new TypeError('invalid pattern')
	  }

	  if (pattern.length > MAX_PATTERN_LENGTH) {
	    throw new TypeError('pattern is too long')
	  }
	};

	// parse a component of the expanded set.
	// At this point, no pattern may contain "/" in it
	// so we're going to return a 2d array, where each entry is the full
	// pattern, split on '/', and then turned into a regular expression.
	// A regexp is made at the end which joins each array with an
	// escaped /, and another full one which joins each regexp with |.
	//
	// Following the lead of Bash 4.1, note that "**" only has special meaning
	// when it is the *only* thing in a path portion.  Otherwise, any series
	// of * is equivalent to a single *.  Globstar behavior is enabled by
	// default, and can be disabled by setting options.noglobstar.
	Minimatch.prototype.parse = parse;
	var SUBPARSE = {};
	function parse (pattern, isSub) {
	  assertValidPattern(pattern);

	  var options = this.options;

	  // shortcuts
	  if (pattern === '**') {
	    if (!options.noglobstar)
	      return GLOBSTAR
	    else
	      pattern = '*';
	  }
	  if (pattern === '') return ''

	  var re = '';
	  var hasMagic = !!options.nocase;
	  var escaping = false;
	  // ? => one single character
	  var patternListStack = [];
	  var negativeLists = [];
	  var stateChar;
	  var inClass = false;
	  var reClassStart = -1;
	  var classStart = -1;
	  // . and .. never match anything that doesn't start with .,
	  // even when options.dot is set.
	  var patternStart = pattern.charAt(0) === '.' ? '' // anything
	  // not (start or / followed by . or .. followed by / or end)
	  : options.dot ? '(?!(?:^|\\\/)\\.{1,2}(?:$|\\\/))'
	  : '(?!\\.)';
	  var self = this;

	  function clearStateChar () {
	    if (stateChar) {
	      // we had some state-tracking character
	      // that wasn't consumed by this pass.
	      switch (stateChar) {
	        case '*':
	          re += star;
	          hasMagic = true;
	        break
	        case '?':
	          re += qmark;
	          hasMagic = true;
	        break
	        default:
	          re += '\\' + stateChar;
	        break
	      }
	      self.debug('clearStateChar %j %j', stateChar, re);
	      stateChar = false;
	    }
	  }

	  for (var i = 0, len = pattern.length, c
	    ; (i < len) && (c = pattern.charAt(i))
	    ; i++) {
	    this.debug('%s\t%s %s %j', pattern, i, re, c);

	    // skip over any that are escaped.
	    if (escaping && reSpecials[c]) {
	      re += '\\' + c;
	      escaping = false;
	      continue
	    }

	    switch (c) {
	      /* istanbul ignore next */
	      case '/': {
	        // completely not allowed, even escaped.
	        // Should already be path-split by now.
	        return false
	      }

	      case '\\':
	        clearStateChar();
	        escaping = true;
	      continue

	      // the various stateChar values
	      // for the "extglob" stuff.
	      case '?':
	      case '*':
	      case '+':
	      case '@':
	      case '!':
	        this.debug('%s\t%s %s %j <-- stateChar', pattern, i, re, c);

	        // all of those are literals inside a class, except that
	        // the glob [!a] means [^a] in regexp
	        if (inClass) {
	          this.debug('  in class');
	          if (c === '!' && i === classStart + 1) c = '^';
	          re += c;
	          continue
	        }

	        // coalesce consecutive non-globstar * characters
	        if (c === '*' && stateChar === '*') continue

	        // if we already have a stateChar, then it means
	        // that there was something like ** or +? in there.
	        // Handle the stateChar, then proceed with this one.
	        self.debug('call clearStateChar %j', stateChar);
	        clearStateChar();
	        stateChar = c;
	        // if extglob is disabled, then +(asdf|foo) isn't a thing.
	        // just clear the statechar *now*, rather than even diving into
	        // the patternList stuff.
	        if (options.noext) clearStateChar();
	      continue

	      case '(':
	        if (inClass) {
	          re += '(';
	          continue
	        }

	        if (!stateChar) {
	          re += '\\(';
	          continue
	        }

	        patternListStack.push({
	          type: stateChar,
	          start: i - 1,
	          reStart: re.length,
	          open: plTypes[stateChar].open,
	          close: plTypes[stateChar].close
	        });
	        // negation is (?:(?!js)[^/]*)
	        re += stateChar === '!' ? '(?:(?!(?:' : '(?:';
	        this.debug('plType %j %j', stateChar, re);
	        stateChar = false;
	      continue

	      case ')':
	        if (inClass || !patternListStack.length) {
	          re += '\\)';
	          continue
	        }

	        clearStateChar();
	        hasMagic = true;
	        var pl = patternListStack.pop();
	        // negation is (?:(?!js)[^/]*)
	        // The others are (?:<pattern>)<type>
	        re += pl.close;
	        if (pl.type === '!') {
	          negativeLists.push(pl);
	        }
	        pl.reEnd = re.length;
	      continue

	      case '|':
	        if (inClass || !patternListStack.length || escaping) {
	          re += '\\|';
	          escaping = false;
	          continue
	        }

	        clearStateChar();
	        re += '|';
	      continue

	      // these are mostly the same in regexp and glob
	      case '[':
	        // swallow any state-tracking char before the [
	        clearStateChar();

	        if (inClass) {
	          re += '\\' + c;
	          continue
	        }

	        inClass = true;
	        classStart = i;
	        reClassStart = re.length;
	        re += c;
	      continue

	      case ']':
	        //  a right bracket shall lose its special
	        //  meaning and represent itself in
	        //  a bracket expression if it occurs
	        //  first in the list.  -- POSIX.2 2.8.3.2
	        if (i === classStart + 1 || !inClass) {
	          re += '\\' + c;
	          escaping = false;
	          continue
	        }

	        // handle the case where we left a class open.
	        // "[z-a]" is valid, equivalent to "\[z-a\]"
	        // split where the last [ was, make sure we don't have
	        // an invalid re. if so, re-walk the contents of the
	        // would-be class to re-translate any characters that
	        // were passed through as-is
	        // TODO: It would probably be faster to determine this
	        // without a try/catch and a new RegExp, but it's tricky
	        // to do safely.  For now, this is safe and works.
	        var cs = pattern.substring(classStart + 1, i);
	        try {
	          RegExp('[' + cs + ']');
	        } catch (er) {
	          // not a valid class!
	          var sp = this.parse(cs, SUBPARSE);
	          re = re.substr(0, reClassStart) + '\\[' + sp[0] + '\\]';
	          hasMagic = hasMagic || sp[1];
	          inClass = false;
	          continue
	        }

	        // finish up the class.
	        hasMagic = true;
	        inClass = false;
	        re += c;
	      continue

	      default:
	        // swallow any state char that wasn't consumed
	        clearStateChar();

	        if (escaping) {
	          // no need
	          escaping = false;
	        } else if (reSpecials[c]
	          && !(c === '^' && inClass)) {
	          re += '\\';
	        }

	        re += c;

	    } // switch
	  } // for

	  // handle the case where we left a class open.
	  // "[abc" is valid, equivalent to "\[abc"
	  if (inClass) {
	    // split where the last [ was, and escape it
	    // this is a huge pita.  We now have to re-walk
	    // the contents of the would-be class to re-translate
	    // any characters that were passed through as-is
	    cs = pattern.substr(classStart + 1);
	    sp = this.parse(cs, SUBPARSE);
	    re = re.substr(0, reClassStart) + '\\[' + sp[0];
	    hasMagic = hasMagic || sp[1];
	  }

	  // handle the case where we had a +( thing at the *end*
	  // of the pattern.
	  // each pattern list stack adds 3 chars, and we need to go through
	  // and escape any | chars that were passed through as-is for the regexp.
	  // Go through and escape them, taking care not to double-escape any
	  // | chars that were already escaped.
	  for (pl = patternListStack.pop(); pl; pl = patternListStack.pop()) {
	    var tail = re.slice(pl.reStart + pl.open.length);
	    this.debug('setting tail', re, pl);
	    // maybe some even number of \, then maybe 1 \, followed by a |
	    tail = tail.replace(/((?:\\{2}){0,64})(\\?)\|/g, function (_, $1, $2) {
	      if (!$2) {
	        // the | isn't already escaped, so escape it.
	        $2 = '\\';
	      }

	      // need to escape all those slashes *again*, without escaping the
	      // one that we need for escaping the | character.  As it works out,
	      // escaping an even number of slashes can be done by simply repeating
	      // it exactly after itself.  That's why this trick works.
	      //
	      // I am sorry that you have to see this.
	      return $1 + $1 + $2 + '|'
	    });

	    this.debug('tail=%j\n   %s', tail, tail, pl, re);
	    var t = pl.type === '*' ? star
	      : pl.type === '?' ? qmark
	      : '\\' + pl.type;

	    hasMagic = true;
	    re = re.slice(0, pl.reStart) + t + '\\(' + tail;
	  }

	  // handle trailing things that only matter at the very end.
	  clearStateChar();
	  if (escaping) {
	    // trailing \\
	    re += '\\\\';
	  }

	  // only need to apply the nodot start if the re starts with
	  // something that could conceivably capture a dot
	  var addPatternStart = false;
	  switch (re.charAt(0)) {
	    case '[': case '.': case '(': addPatternStart = true;
	  }

	  // Hack to work around lack of negative lookbehind in JS
	  // A pattern like: *.!(x).!(y|z) needs to ensure that a name
	  // like 'a.xyz.yz' doesn't match.  So, the first negative
	  // lookahead, has to look ALL the way ahead, to the end of
	  // the pattern.
	  for (var n = negativeLists.length - 1; n > -1; n--) {
	    var nl = negativeLists[n];

	    var nlBefore = re.slice(0, nl.reStart);
	    var nlFirst = re.slice(nl.reStart, nl.reEnd - 8);
	    var nlLast = re.slice(nl.reEnd - 8, nl.reEnd);
	    var nlAfter = re.slice(nl.reEnd);

	    nlLast += nlAfter;

	    // Handle nested stuff like *(*.js|!(*.json)), where open parens
	    // mean that we should *not* include the ) in the bit that is considered
	    // "after" the negated section.
	    var openParensBefore = nlBefore.split('(').length - 1;
	    var cleanAfter = nlAfter;
	    for (i = 0; i < openParensBefore; i++) {
	      cleanAfter = cleanAfter.replace(/\)[+*?]?/, '');
	    }
	    nlAfter = cleanAfter;

	    var dollar = '';
	    if (nlAfter === '' && isSub !== SUBPARSE) {
	      dollar = '$';
	    }
	    var newRe = nlBefore + nlFirst + nlAfter + dollar + nlLast;
	    re = newRe;
	  }

	  // if the re is not "" at this point, then we need to make sure
	  // it doesn't match against an empty path part.
	  // Otherwise a/* will match a/, which it should not.
	  if (re !== '' && hasMagic) {
	    re = '(?=.)' + re;
	  }

	  if (addPatternStart) {
	    re = patternStart + re;
	  }

	  // parsing just a piece of a larger pattern.
	  if (isSub === SUBPARSE) {
	    return [re, hasMagic]
	  }

	  // skip the regexp for non-magical patterns
	  // unescape anything in it, though, so that it'll be
	  // an exact match against a file etc.
	  if (!hasMagic) {
	    return globUnescape(pattern)
	  }

	  var flags = options.nocase ? 'i' : '';
	  try {
	    var regExp = new RegExp('^' + re + '$', flags);
	  } catch (er) /* istanbul ignore next - should be impossible */ {
	    // If it was an invalid regular expression, then it can't match
	    // anything.  This trick looks for a character after the end of
	    // the string, which is of course impossible, except in multi-line
	    // mode, but it's not a /m regex.
	    return new RegExp('$.')
	  }

	  regExp._glob = pattern;
	  regExp._src = re;

	  return regExp
	}

	minimatch.makeRe = function (pattern, options) {
	  return new Minimatch(pattern, options || {}).makeRe()
	};

	Minimatch.prototype.makeRe = makeRe;
	function makeRe () {
	  if (this.regexp || this.regexp === false) return this.regexp

	  // at this point, this.set is a 2d array of partial
	  // pattern strings, or "**".
	  //
	  // It's better to use .match().  This function shouldn't
	  // be used, really, but it's pretty convenient sometimes,
	  // when you just want to work with a regex.
	  var set = this.set;

	  if (!set.length) {
	    this.regexp = false;
	    return this.regexp
	  }
	  var options = this.options;

	  var twoStar = options.noglobstar ? star
	    : options.dot ? twoStarDot
	    : twoStarNoDot;
	  var flags = options.nocase ? 'i' : '';

	  var re = set.map(function (pattern) {
	    return pattern.map(function (p) {
	      return (p === GLOBSTAR) ? twoStar
	      : (typeof p === 'string') ? regExpEscape(p)
	      : p._src
	    }).join('\\\/')
	  }).join('|');

	  // must match entire pattern
	  // ending in a * or ** will make it less strict.
	  re = '^(?:' + re + ')$';

	  // can match anything, as long as it's not this.
	  if (this.negate) re = '^(?!' + re + ').*$';

	  try {
	    this.regexp = new RegExp(re, flags);
	  } catch (ex) /* istanbul ignore next - should be impossible */ {
	    this.regexp = false;
	  }
	  return this.regexp
	}

	minimatch.match = function (list, pattern, options) {
	  options = options || {};
	  var mm = new Minimatch(pattern, options);
	  list = list.filter(function (f) {
	    return mm.match(f)
	  });
	  if (mm.options.nonull && !list.length) {
	    list.push(pattern);
	  }
	  return list
	};

	Minimatch.prototype.match = function match (f, partial) {
	  if (typeof partial === 'undefined') partial = this.partial;
	  this.debug('match', f, this.pattern);
	  // short-circuit in the case of busted things.
	  // comments, etc.
	  if (this.comment) return false
	  if (this.empty) return f === ''

	  if (f === '/' && partial) return true

	  var options = this.options;

	  // windows: need to use /, not \
	  if (path.sep !== '/') {
	    f = f.split(path.sep).join('/');
	  }

	  // treat the test path as a set of pathparts.
	  f = f.split(slashSplit);
	  this.debug(this.pattern, 'split', f);

	  // just ONE of the pattern sets in this.set needs to match
	  // in order for it to be valid.  If negating, then just one
	  // match means that we have failed.
	  // Either way, return on the first hit.

	  var set = this.set;
	  this.debug(this.pattern, 'set', set);

	  // Find the basename of the path by looking for the last non-empty segment
	  var filename;
	  var i;
	  for (i = f.length - 1; i >= 0; i--) {
	    filename = f[i];
	    if (filename) break
	  }

	  for (i = 0; i < set.length; i++) {
	    var pattern = set[i];
	    var file = f;
	    if (options.matchBase && pattern.length === 1) {
	      file = [filename];
	    }
	    var hit = this.matchOne(file, pattern, partial);
	    if (hit) {
	      if (options.flipNegate) return true
	      return !this.negate
	    }
	  }

	  // didn't get any hits.  this is success if it's a negative
	  // pattern, failure otherwise.
	  if (options.flipNegate) return false
	  return this.negate
	};

	// set partial to true to test if, for example,
	// "/a/b" matches the start of "/*/b/*/d"
	// Partial means, if you run out of file before you run
	// out of pattern, then that's fine, as long as all
	// the parts match.
	Minimatch.prototype.matchOne = function (file, pattern, partial) {
	  if (pattern.indexOf(GLOBSTAR) !== -1) {
	    return this._matchGlobstar(file, pattern, partial, 0, 0)
	  }
	  return this._matchOne(file, pattern, partial, 0, 0)
	};

	Minimatch.prototype._matchGlobstar = function (file, pattern, partial, fileIndex, patternIndex) {
	  var i;

	  // find first globstar from patternIndex
	  var firstgs = -1;
	  for (i = patternIndex; i < pattern.length; i++) {
	    if (pattern[i] === GLOBSTAR) { firstgs = i; break }
	  }

	  // find last globstar
	  var lastgs = -1;
	  for (i = pattern.length - 1; i >= 0; i--) {
	    if (pattern[i] === GLOBSTAR) { lastgs = i; break }
	  }

	  var head = pattern.slice(patternIndex, firstgs);
	  var body = partial ? pattern.slice(firstgs + 1) : pattern.slice(firstgs + 1, lastgs);
	  var tail = partial ? [] : pattern.slice(lastgs + 1);

	  // check the head
	  if (head.length) {
	    var fileHead = file.slice(fileIndex, fileIndex + head.length);
	    if (!this._matchOne(fileHead, head, partial, 0, 0)) {
	      return false
	    }
	    fileIndex += head.length;
	  }

	  // check the tail
	  var fileTailMatch = 0;
	  if (tail.length) {
	    if (tail.length + fileIndex > file.length) return false

	    var tailStart = file.length - tail.length;
	    if (this._matchOne(file, tail, partial, tailStart, 0)) {
	      fileTailMatch = tail.length;
	    } else {
	      // affordance for stuff like a/**/* matching a/b/
	      if (file[file.length - 1] !== '' ||
	          fileIndex + tail.length === file.length) {
	        return false
	      }
	      tailStart--;
	      if (!this._matchOne(file, tail, partial, tailStart, 0)) {
	        return false
	      }
	      fileTailMatch = tail.length + 1;
	    }
	  }

	  // if body is empty (single ** between head and tail)
	  if (!body.length) {
	    var sawSome = !!fileTailMatch;
	    for (i = fileIndex; i < file.length - fileTailMatch; i++) {
	      var f = String(file[i]);
	      sawSome = true;
	      if (f === '.' || f === '..' ||
	          (!this.options.dot && f.charAt(0) === '.')) {
	        return false
	      }
	    }
	    return partial || sawSome
	  }

	  // split body into segments at each GLOBSTAR
	  var bodySegments = [[[], 0]];
	  var currentBody = bodySegments[0];
	  var nonGsParts = 0;
	  var nonGsPartsSums = [0];
	  for (var bi = 0; bi < body.length; bi++) {
	    var b = body[bi];
	    if (b === GLOBSTAR) {
	      nonGsPartsSums.push(nonGsParts);
	      currentBody = [[], 0];
	      bodySegments.push(currentBody);
	    } else {
	      currentBody[0].push(b);
	      nonGsParts++;
	    }
	  }

	  var idx = bodySegments.length - 1;
	  var fileLength = file.length - fileTailMatch;
	  for (var si = 0; si < bodySegments.length; si++) {
	    bodySegments[si][1] = fileLength -
	      (nonGsPartsSums[idx--] + bodySegments[si][0].length);
	  }

	  return !!this._matchGlobStarBodySections(
	    file, bodySegments, fileIndex, 0, partial, 0, !!fileTailMatch
	  )
	};

	// return false for "nope, not matching"
	// return null for "not matching, cannot keep trying"
	Minimatch.prototype._matchGlobStarBodySections = function (
	  file, bodySegments, fileIndex, bodyIndex, partial, globStarDepth, sawTail
	) {
	  var bs = bodySegments[bodyIndex];
	  if (!bs) {
	    // just make sure there are no bad dots
	    for (var i = fileIndex; i < file.length; i++) {
	      sawTail = true;
	      var f = file[i];
	      if (f === '.' || f === '..' ||
	          (!this.options.dot && f.charAt(0) === '.')) {
	        return false
	      }
	    }
	    return sawTail
	  }

	  var body = bs[0];
	  var after = bs[1];
	  while (fileIndex <= after) {
	    var m = this._matchOne(
	      file.slice(0, fileIndex + body.length),
	      body,
	      partial,
	      fileIndex,
	      0
	    );
	    // if limit exceeded, no match. intentional false negative,
	    // acceptable break in correctness for security.
	    if (m && globStarDepth < this.maxGlobstarRecursion) {
	      var sub = this._matchGlobStarBodySections(
	        file, bodySegments,
	        fileIndex + body.length, bodyIndex + 1,
	        partial, globStarDepth + 1, sawTail
	      );
	      if (sub !== false) {
	        return sub
	      }
	    }
	    var f = file[fileIndex];
	    if (f === '.' || f === '..' ||
	        (!this.options.dot && f.charAt(0) === '.')) {
	      return false
	    }
	    fileIndex++;
	  }
	  return partial || null
	};

	Minimatch.prototype._matchOne = function (file, pattern, partial, fileIndex, patternIndex) {
	  var fi, pi, fl, pl;
	  for (
	    fi = fileIndex, pi = patternIndex, fl = file.length, pl = pattern.length
	    ; (fi < fl) && (pi < pl)
	    ; fi++, pi++
	  ) {
	    this.debug('matchOne loop');
	    var p = pattern[pi];
	    var f = file[fi];

	    this.debug(pattern, p, f);

	    // should be impossible.
	    // some invalid regexp stuff in the set.
	    /* istanbul ignore if */
	    if (p === false || p === GLOBSTAR) return false

	    // something other than **
	    // non-magic patterns just have to match exactly
	    // patterns with magic have been turned into regexps.
	    var hit;
	    if (typeof p === 'string') {
	      hit = f === p;
	      this.debug('string match', p, f, hit);
	    } else {
	      hit = f.match(p);
	      this.debug('pattern match', p, f, hit);
	    }

	    if (!hit) return false
	  }

	  // now either we fell off the end of the pattern, or we're done.
	  if (fi === fl && pi === pl) {
	    // ran out of pattern and filename at the same time.
	    // an exact hit!
	    return true
	  } else if (fi === fl) {
	    // ran out of file, but still had pattern left.
	    // this is ok if we're doing the match as part of
	    // a glob fs traversal.
	    return partial
	  } else /* istanbul ignore else */ if (pi === pl) {
	    // ran out of pattern, still have file left.
	    // this is only acceptable if we're on the very last
	    // empty segment of a file with a trailing slash.
	    // a/* should match a/b/
	    return (fi === fl - 1) && (file[fi] === '')
	  }

	  // should be unreachable.
	  /* istanbul ignore next */
	  throw new Error('wtf?')
	};

	// replace stuff like \* with *
	function globUnescape (s) {
	  return s.replace(/\\(.)/g, '$1')
	}

	function regExpEscape (s) {
	  return s.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&')
	}
	return minimatch_1;
}

var dist$2 = {};

var dist$1 = {};

var helpers = {};

var hasRequiredHelpers;

function requireHelpers () {
	if (hasRequiredHelpers) return helpers;
	hasRequiredHelpers = 1;
	var __createBinding = (helpers && helpers.__createBinding) || (Object.create ? (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    var desc = Object.getOwnPropertyDescriptor(m, k);
	    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
	      desc = { enumerable: true, get: function() { return m[k]; } };
	    }
	    Object.defineProperty(o, k2, desc);
	}) : (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    o[k2] = m[k];
	}));
	var __setModuleDefault = (helpers && helpers.__setModuleDefault) || (Object.create ? (function(o, v) {
	    Object.defineProperty(o, "default", { enumerable: true, value: v });
	}) : function(o, v) {
	    o["default"] = v;
	});
	var __importStar = (helpers && helpers.__importStar) || function (mod) {
	    if (mod && mod.__esModule) return mod;
	    var result = {};
	    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
	    __setModuleDefault(result, mod);
	    return result;
	};
	Object.defineProperty(helpers, "__esModule", { value: true });
	helpers.req = helpers.json = helpers.toBuffer = void 0;
	const http = __importStar(http__default);
	const https = __importStar(https__default);
	async function toBuffer(stream) {
	    let length = 0;
	    const chunks = [];
	    for await (const chunk of stream) {
	        length += chunk.length;
	        chunks.push(chunk);
	    }
	    return Buffer.concat(chunks, length);
	}
	helpers.toBuffer = toBuffer;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	async function json(stream) {
	    const buf = await toBuffer(stream);
	    const str = buf.toString('utf8');
	    try {
	        return JSON.parse(str);
	    }
	    catch (_err) {
	        const err = _err;
	        err.message += ` (input: ${str})`;
	        throw err;
	    }
	}
	helpers.json = json;
	function req(url, opts = {}) {
	    const href = typeof url === 'string' ? url : url.href;
	    const req = (href.startsWith('https:') ? https : http).request(url, opts);
	    const promise = new Promise((resolve, reject) => {
	        req
	            .once('response', resolve)
	            .once('error', reject)
	            .end();
	    });
	    req.then = promise.then.bind(promise);
	    return req;
	}
	helpers.req = req;
	
	return helpers;
}

var hasRequiredDist$2;

function requireDist$2 () {
	if (hasRequiredDist$2) return dist$1;
	hasRequiredDist$2 = 1;
	(function (exports) {
		var __createBinding = (dist$1 && dist$1.__createBinding) || (Object.create ? (function(o, m, k, k2) {
		    if (k2 === undefined) k2 = k;
		    var desc = Object.getOwnPropertyDescriptor(m, k);
		    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
		      desc = { enumerable: true, get: function() { return m[k]; } };
		    }
		    Object.defineProperty(o, k2, desc);
		}) : (function(o, m, k, k2) {
		    if (k2 === undefined) k2 = k;
		    o[k2] = m[k];
		}));
		var __setModuleDefault = (dist$1 && dist$1.__setModuleDefault) || (Object.create ? (function(o, v) {
		    Object.defineProperty(o, "default", { enumerable: true, value: v });
		}) : function(o, v) {
		    o["default"] = v;
		});
		var __importStar = (dist$1 && dist$1.__importStar) || function (mod) {
		    if (mod && mod.__esModule) return mod;
		    var result = {};
		    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
		    __setModuleDefault(result, mod);
		    return result;
		};
		var __exportStar = (dist$1 && dist$1.__exportStar) || function(m, exports) {
		    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
		};
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.Agent = void 0;
		const net = __importStar(require$$0);
		const http = __importStar(http__default);
		const https_1 = https__default;
		__exportStar(requireHelpers(), exports);
		const INTERNAL = Symbol('AgentBaseInternalState');
		class Agent extends http.Agent {
		    constructor(opts) {
		        super(opts);
		        this[INTERNAL] = {};
		    }
		    /**
		     * Determine whether this is an `http` or `https` request.
		     */
		    isSecureEndpoint(options) {
		        if (options) {
		            // First check the `secureEndpoint` property explicitly, since this
		            // means that a parent `Agent` is "passing through" to this instance.
		            // eslint-disable-next-line @typescript-eslint/no-explicit-any
		            if (typeof options.secureEndpoint === 'boolean') {
		                return options.secureEndpoint;
		            }
		            // If no explicit `secure` endpoint, check if `protocol` property is
		            // set. This will usually be the case since using a full string URL
		            // or `URL` instance should be the most common usage.
		            if (typeof options.protocol === 'string') {
		                return options.protocol === 'https:';
		            }
		        }
		        // Finally, if no `protocol` property was set, then fall back to
		        // checking the stack trace of the current call stack, and try to
		        // detect the "https" module.
		        const { stack } = new Error();
		        if (typeof stack !== 'string')
		            return false;
		        return stack
		            .split('\n')
		            .some((l) => l.indexOf('(https.js:') !== -1 ||
		            l.indexOf('node:https:') !== -1);
		    }
		    // In order to support async signatures in `connect()` and Node's native
		    // connection pooling in `http.Agent`, the array of sockets for each origin
		    // has to be updated synchronously. This is so the length of the array is
		    // accurate when `addRequest()` is next called. We achieve this by creating a
		    // fake socket and adding it to `sockets[origin]` and incrementing
		    // `totalSocketCount`.
		    incrementSockets(name) {
		        // If `maxSockets` and `maxTotalSockets` are both Infinity then there is no
		        // need to create a fake socket because Node.js native connection pooling
		        // will never be invoked.
		        if (this.maxSockets === Infinity && this.maxTotalSockets === Infinity) {
		            return null;
		        }
		        // All instances of `sockets` are expected TypeScript errors. The
		        // alternative is to add it as a private property of this class but that
		        // will break TypeScript subclassing.
		        if (!this.sockets[name]) {
		            // @ts-expect-error `sockets` is readonly in `@types/node`
		            this.sockets[name] = [];
		        }
		        const fakeSocket = new net.Socket({ writable: false });
		        this.sockets[name].push(fakeSocket);
		        // @ts-expect-error `totalSocketCount` isn't defined in `@types/node`
		        this.totalSocketCount++;
		        return fakeSocket;
		    }
		    decrementSockets(name, socket) {
		        if (!this.sockets[name] || socket === null) {
		            return;
		        }
		        const sockets = this.sockets[name];
		        const index = sockets.indexOf(socket);
		        if (index !== -1) {
		            sockets.splice(index, 1);
		            // @ts-expect-error  `totalSocketCount` isn't defined in `@types/node`
		            this.totalSocketCount--;
		            if (sockets.length === 0) {
		                // @ts-expect-error `sockets` is readonly in `@types/node`
		                delete this.sockets[name];
		            }
		        }
		    }
		    // In order to properly update the socket pool, we need to call `getName()` on
		    // the core `https.Agent` if it is a secureEndpoint.
		    getName(options) {
		        const secureEndpoint = typeof options.secureEndpoint === 'boolean'
		            ? options.secureEndpoint
		            : this.isSecureEndpoint(options);
		        if (secureEndpoint) {
		            // @ts-expect-error `getName()` isn't defined in `@types/node`
		            return https_1.Agent.prototype.getName.call(this, options);
		        }
		        // @ts-expect-error `getName()` isn't defined in `@types/node`
		        return super.getName(options);
		    }
		    createSocket(req, options, cb) {
		        const connectOpts = {
		            ...options,
		            secureEndpoint: this.isSecureEndpoint(options),
		        };
		        const name = this.getName(connectOpts);
		        const fakeSocket = this.incrementSockets(name);
		        Promise.resolve()
		            .then(() => this.connect(req, connectOpts))
		            .then((socket) => {
		            this.decrementSockets(name, fakeSocket);
		            if (socket instanceof http.Agent) {
		                try {
		                    // @ts-expect-error `addRequest()` isn't defined in `@types/node`
		                    return socket.addRequest(req, connectOpts);
		                }
		                catch (err) {
		                    return cb(err);
		                }
		            }
		            this[INTERNAL].currentSocket = socket;
		            // @ts-expect-error `createSocket()` isn't defined in `@types/node`
		            super.createSocket(req, options, cb);
		        }, (err) => {
		            this.decrementSockets(name, fakeSocket);
		            cb(err);
		        });
		    }
		    createConnection() {
		        const socket = this[INTERNAL].currentSocket;
		        this[INTERNAL].currentSocket = undefined;
		        if (!socket) {
		            throw new Error('No socket was returned in the `connect()` function');
		        }
		        return socket;
		    }
		    get defaultPort() {
		        return (this[INTERNAL].defaultPort ??
		            (this.protocol === 'https:' ? 443 : 80));
		    }
		    set defaultPort(v) {
		        if (this[INTERNAL]) {
		            this[INTERNAL].defaultPort = v;
		        }
		    }
		    get protocol() {
		        return (this[INTERNAL].protocol ??
		            (this.isSecureEndpoint() ? 'https:' : 'http:'));
		    }
		    set protocol(v) {
		        if (this[INTERNAL]) {
		            this[INTERNAL].protocol = v;
		        }
		    }
		}
		exports.Agent = Agent;
		
	} (dist$1));
	return dist$1;
}

var parseProxyResponse = {};

var hasRequiredParseProxyResponse;

function requireParseProxyResponse () {
	if (hasRequiredParseProxyResponse) return parseProxyResponse;
	hasRequiredParseProxyResponse = 1;
	var __importDefault = (parseProxyResponse && parseProxyResponse.__importDefault) || function (mod) {
	    return (mod && mod.__esModule) ? mod : { "default": mod };
	};
	Object.defineProperty(parseProxyResponse, "__esModule", { value: true });
	parseProxyResponse.parseProxyResponse = void 0;
	const debug_1 = __importDefault(requireSrc());
	const debug = (0, debug_1.default)('https-proxy-agent:parse-proxy-response');
	function parseProxyResponse$1(socket) {
	    return new Promise((resolve, reject) => {
	        // we need to buffer any HTTP traffic that happens with the proxy before we get
	        // the CONNECT response, so that if the response is anything other than an "200"
	        // response code, then we can re-play the "data" events on the socket once the
	        // HTTP parser is hooked up...
	        let buffersLength = 0;
	        const buffers = [];
	        function read() {
	            const b = socket.read();
	            if (b)
	                ondata(b);
	            else
	                socket.once('readable', read);
	        }
	        function cleanup() {
	            socket.removeListener('end', onend);
	            socket.removeListener('error', onerror);
	            socket.removeListener('readable', read);
	        }
	        function onend() {
	            cleanup();
	            debug('onend');
	            reject(new Error('Proxy connection ended before receiving CONNECT response'));
	        }
	        function onerror(err) {
	            cleanup();
	            debug('onerror %o', err);
	            reject(err);
	        }
	        function ondata(b) {
	            buffers.push(b);
	            buffersLength += b.length;
	            const buffered = Buffer.concat(buffers, buffersLength);
	            const endOfHeaders = buffered.indexOf('\r\n\r\n');
	            if (endOfHeaders === -1) {
	                // keep buffering
	                debug('have not received end of HTTP headers yet...');
	                read();
	                return;
	            }
	            const headerParts = buffered
	                .slice(0, endOfHeaders)
	                .toString('ascii')
	                .split('\r\n');
	            const firstLine = headerParts.shift();
	            if (!firstLine) {
	                socket.destroy();
	                return reject(new Error('No header received from proxy CONNECT response'));
	            }
	            const firstLineParts = firstLine.split(' ');
	            const statusCode = +firstLineParts[1];
	            const statusText = firstLineParts.slice(2).join(' ');
	            const headers = {};
	            for (const header of headerParts) {
	                if (!header)
	                    continue;
	                const firstColon = header.indexOf(':');
	                if (firstColon === -1) {
	                    socket.destroy();
	                    return reject(new Error(`Invalid header from proxy CONNECT response: "${header}"`));
	                }
	                const key = header.slice(0, firstColon).toLowerCase();
	                const value = header.slice(firstColon + 1).trimStart();
	                const current = headers[key];
	                if (typeof current === 'string') {
	                    headers[key] = [current, value];
	                }
	                else if (Array.isArray(current)) {
	                    current.push(value);
	                }
	                else {
	                    headers[key] = value;
	                }
	            }
	            debug('got proxy server response: %o %o', firstLine, headers);
	            cleanup();
	            resolve({
	                connect: {
	                    statusCode,
	                    statusText,
	                    headers,
	                },
	                buffered,
	            });
	        }
	        socket.on('error', onerror);
	        socket.on('end', onend);
	        read();
	    });
	}
	parseProxyResponse.parseProxyResponse = parseProxyResponse$1;
	
	return parseProxyResponse;
}

var hasRequiredDist$1;

function requireDist$1 () {
	if (hasRequiredDist$1) return dist$2;
	hasRequiredDist$1 = 1;
	var __createBinding = (dist$2 && dist$2.__createBinding) || (Object.create ? (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    var desc = Object.getOwnPropertyDescriptor(m, k);
	    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
	      desc = { enumerable: true, get: function() { return m[k]; } };
	    }
	    Object.defineProperty(o, k2, desc);
	}) : (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    o[k2] = m[k];
	}));
	var __setModuleDefault = (dist$2 && dist$2.__setModuleDefault) || (Object.create ? (function(o, v) {
	    Object.defineProperty(o, "default", { enumerable: true, value: v });
	}) : function(o, v) {
	    o["default"] = v;
	});
	var __importStar = (dist$2 && dist$2.__importStar) || function (mod) {
	    if (mod && mod.__esModule) return mod;
	    var result = {};
	    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
	    __setModuleDefault(result, mod);
	    return result;
	};
	var __importDefault = (dist$2 && dist$2.__importDefault) || function (mod) {
	    return (mod && mod.__esModule) ? mod : { "default": mod };
	};
	Object.defineProperty(dist$2, "__esModule", { value: true });
	dist$2.HttpsProxyAgent = void 0;
	const net = __importStar(require$$0);
	const tls = __importStar(require$$1);
	const assert_1 = __importDefault(assert);
	const debug_1 = __importDefault(requireSrc());
	const agent_base_1 = requireDist$2();
	const url_1 = require$$2;
	const parse_proxy_response_1 = requireParseProxyResponse();
	const debug = (0, debug_1.default)('https-proxy-agent');
	const setServernameFromNonIpHost = (options) => {
	    if (options.servername === undefined &&
	        options.host &&
	        !net.isIP(options.host)) {
	        return {
	            ...options,
	            servername: options.host,
	        };
	    }
	    return options;
	};
	/**
	 * The `HttpsProxyAgent` implements an HTTP Agent subclass that connects to
	 * the specified "HTTP(s) proxy server" in order to proxy HTTPS requests.
	 *
	 * Outgoing HTTP requests are first tunneled through the proxy server using the
	 * `CONNECT` HTTP request method to establish a connection to the proxy server,
	 * and then the proxy server connects to the destination target and issues the
	 * HTTP request from the proxy server.
	 *
	 * `https:` requests have their socket connection upgraded to TLS once
	 * the connection to the proxy server has been established.
	 */
	class HttpsProxyAgent extends agent_base_1.Agent {
	    constructor(proxy, opts) {
	        super(opts);
	        this.options = { path: undefined };
	        this.proxy = typeof proxy === 'string' ? new url_1.URL(proxy) : proxy;
	        this.proxyHeaders = opts?.headers ?? {};
	        debug('Creating new HttpsProxyAgent instance: %o', this.proxy.href);
	        // Trim off the brackets from IPv6 addresses
	        const host = (this.proxy.hostname || this.proxy.host).replace(/^\[|\]$/g, '');
	        const port = this.proxy.port
	            ? parseInt(this.proxy.port, 10)
	            : this.proxy.protocol === 'https:'
	                ? 443
	                : 80;
	        this.connectOpts = {
	            // Attempt to negotiate http/1.1 for proxy servers that support http/2
	            ALPNProtocols: ['http/1.1'],
	            ...(opts ? omit(opts, 'headers') : null),
	            host,
	            port,
	        };
	    }
	    /**
	     * Called when the node-core HTTP client library is creating a
	     * new HTTP request.
	     */
	    async connect(req, opts) {
	        const { proxy } = this;
	        if (!opts.host) {
	            throw new TypeError('No "host" provided');
	        }
	        // Create a socket connection to the proxy server.
	        let socket;
	        if (proxy.protocol === 'https:') {
	            debug('Creating `tls.Socket`: %o', this.connectOpts);
	            socket = tls.connect(setServernameFromNonIpHost(this.connectOpts));
	        }
	        else {
	            debug('Creating `net.Socket`: %o', this.connectOpts);
	            socket = net.connect(this.connectOpts);
	        }
	        const headers = typeof this.proxyHeaders === 'function'
	            ? this.proxyHeaders()
	            : { ...this.proxyHeaders };
	        const host = net.isIPv6(opts.host) ? `[${opts.host}]` : opts.host;
	        let payload = `CONNECT ${host}:${opts.port} HTTP/1.1\r\n`;
	        // Inject the `Proxy-Authorization` header if necessary.
	        if (proxy.username || proxy.password) {
	            const auth = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
	            headers['Proxy-Authorization'] = `Basic ${Buffer.from(auth).toString('base64')}`;
	        }
	        headers.Host = `${host}:${opts.port}`;
	        if (!headers['Proxy-Connection']) {
	            headers['Proxy-Connection'] = this.keepAlive
	                ? 'Keep-Alive'
	                : 'close';
	        }
	        for (const name of Object.keys(headers)) {
	            payload += `${name}: ${headers[name]}\r\n`;
	        }
	        const proxyResponsePromise = (0, parse_proxy_response_1.parseProxyResponse)(socket);
	        socket.write(`${payload}\r\n`);
	        const { connect, buffered } = await proxyResponsePromise;
	        req.emit('proxyConnect', connect);
	        this.emit('proxyConnect', connect, req);
	        if (connect.statusCode === 200) {
	            req.once('socket', resume);
	            if (opts.secureEndpoint) {
	                // The proxy is connecting to a TLS server, so upgrade
	                // this socket connection to a TLS connection.
	                debug('Upgrading socket connection to TLS');
	                return tls.connect({
	                    ...omit(setServernameFromNonIpHost(opts), 'host', 'path', 'port'),
	                    socket,
	                });
	            }
	            return socket;
	        }
	        // Some other status code that's not 200... need to re-play the HTTP
	        // header "data" events onto the socket once the HTTP machinery is
	        // attached so that the node core `http` can parse and handle the
	        // error status code.
	        // Close the original socket, and a new "fake" socket is returned
	        // instead, so that the proxy doesn't get the HTTP request
	        // written to it (which may contain `Authorization` headers or other
	        // sensitive data).
	        //
	        // See: https://hackerone.com/reports/541502
	        socket.destroy();
	        const fakeSocket = new net.Socket({ writable: false });
	        fakeSocket.readable = true;
	        // Need to wait for the "socket" event to re-play the "data" events.
	        req.once('socket', (s) => {
	            debug('Replaying proxy buffer for failed request');
	            (0, assert_1.default)(s.listenerCount('data') > 0);
	            // Replay the "buffered" Buffer onto the fake `socket`, since at
	            // this point the HTTP module machinery has been hooked up for
	            // the user.
	            s.push(buffered);
	            s.push(null);
	        });
	        return fakeSocket;
	    }
	}
	HttpsProxyAgent.protocols = ['http', 'https'];
	dist$2.HttpsProxyAgent = HttpsProxyAgent;
	function resume(socket) {
	    socket.resume();
	}
	function omit(obj, ...keys) {
	    const ret = {};
	    let key;
	    for (key in obj) {
	        if (!keys.includes(key)) {
	            ret[key] = obj[key];
	        }
	    }
	    return ret;
	}
	
	return dist$2;
}

var dist = {};

var hasRequiredDist;

function requireDist () {
	if (hasRequiredDist) return dist;
	hasRequiredDist = 1;
	var __createBinding = (dist && dist.__createBinding) || (Object.create ? (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    var desc = Object.getOwnPropertyDescriptor(m, k);
	    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
	      desc = { enumerable: true, get: function() { return m[k]; } };
	    }
	    Object.defineProperty(o, k2, desc);
	}) : (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    o[k2] = m[k];
	}));
	var __setModuleDefault = (dist && dist.__setModuleDefault) || (Object.create ? (function(o, v) {
	    Object.defineProperty(o, "default", { enumerable: true, value: v });
	}) : function(o, v) {
	    o["default"] = v;
	});
	var __importStar = (dist && dist.__importStar) || function (mod) {
	    if (mod && mod.__esModule) return mod;
	    var result = {};
	    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
	    __setModuleDefault(result, mod);
	    return result;
	};
	var __importDefault = (dist && dist.__importDefault) || function (mod) {
	    return (mod && mod.__esModule) ? mod : { "default": mod };
	};
	Object.defineProperty(dist, "__esModule", { value: true });
	dist.HttpProxyAgent = void 0;
	const net = __importStar(require$$0);
	const tls = __importStar(require$$1);
	const debug_1 = __importDefault(requireSrc());
	const events_1 = require$$0__default;
	const agent_base_1 = requireDist$2();
	const url_1 = require$$2;
	const debug = (0, debug_1.default)('http-proxy-agent');
	/**
	 * The `HttpProxyAgent` implements an HTTP Agent subclass that connects
	 * to the specified "HTTP proxy server" in order to proxy HTTP requests.
	 */
	class HttpProxyAgent extends agent_base_1.Agent {
	    constructor(proxy, opts) {
	        super(opts);
	        this.proxy = typeof proxy === 'string' ? new url_1.URL(proxy) : proxy;
	        this.proxyHeaders = opts?.headers ?? {};
	        debug('Creating new HttpProxyAgent instance: %o', this.proxy.href);
	        // Trim off the brackets from IPv6 addresses
	        const host = (this.proxy.hostname || this.proxy.host).replace(/^\[|\]$/g, '');
	        const port = this.proxy.port
	            ? parseInt(this.proxy.port, 10)
	            : this.proxy.protocol === 'https:'
	                ? 443
	                : 80;
	        this.connectOpts = {
	            ...(opts ? omit(opts, 'headers') : null),
	            host,
	            port,
	        };
	    }
	    addRequest(req, opts) {
	        req._header = null;
	        this.setRequestProps(req, opts);
	        // @ts-expect-error `addRequest()` isn't defined in `@types/node`
	        super.addRequest(req, opts);
	    }
	    setRequestProps(req, opts) {
	        const { proxy } = this;
	        const protocol = opts.secureEndpoint ? 'https:' : 'http:';
	        const hostname = req.getHeader('host') || 'localhost';
	        const base = `${protocol}//${hostname}`;
	        const url = new url_1.URL(req.path, base);
	        if (opts.port !== 80) {
	            url.port = String(opts.port);
	        }
	        // Change the `http.ClientRequest` instance's "path" field
	        // to the absolute path of the URL that will be requested.
	        req.path = String(url);
	        // Inject the `Proxy-Authorization` header if necessary.
	        const headers = typeof this.proxyHeaders === 'function'
	            ? this.proxyHeaders()
	            : { ...this.proxyHeaders };
	        if (proxy.username || proxy.password) {
	            const auth = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
	            headers['Proxy-Authorization'] = `Basic ${Buffer.from(auth).toString('base64')}`;
	        }
	        if (!headers['Proxy-Connection']) {
	            headers['Proxy-Connection'] = this.keepAlive
	                ? 'Keep-Alive'
	                : 'close';
	        }
	        for (const name of Object.keys(headers)) {
	            const value = headers[name];
	            if (value) {
	                req.setHeader(name, value);
	            }
	        }
	    }
	    async connect(req, opts) {
	        req._header = null;
	        if (!req.path.includes('://')) {
	            this.setRequestProps(req, opts);
	        }
	        // At this point, the http ClientRequest's internal `_header` field
	        // might have already been set. If this is the case then we'll need
	        // to re-generate the string since we just changed the `req.path`.
	        let first;
	        let endOfHeaders;
	        debug('Regenerating stored HTTP header string for request');
	        req._implicitHeader();
	        if (req.outputData && req.outputData.length > 0) {
	            debug('Patching connection write() output buffer with updated header');
	            first = req.outputData[0].data;
	            endOfHeaders = first.indexOf('\r\n\r\n') + 4;
	            req.outputData[0].data =
	                req._header + first.substring(endOfHeaders);
	            debug('Output buffer: %o', req.outputData[0].data);
	        }
	        // Create a socket connection to the proxy server.
	        let socket;
	        if (this.proxy.protocol === 'https:') {
	            debug('Creating `tls.Socket`: %o', this.connectOpts);
	            socket = tls.connect(this.connectOpts);
	        }
	        else {
	            debug('Creating `net.Socket`: %o', this.connectOpts);
	            socket = net.connect(this.connectOpts);
	        }
	        // Wait for the socket's `connect` event, so that this `callback()`
	        // function throws instead of the `http` request machinery. This is
	        // important for i.e. `PacProxyAgent` which determines a failed proxy
	        // connection via the `callback()` function throwing.
	        await (0, events_1.once)(socket, 'connect');
	        return socket;
	    }
	}
	HttpProxyAgent.protocols = ['http', 'https'];
	dist.HttpProxyAgent = HttpProxyAgent;
	function omit(obj, ...keys) {
	    const ret = {};
	    let key;
	    for (key in obj) {
	        if (!keys.includes(key)) {
	            ret[key] = obj[key];
	        }
	    }
	    return ret;
	}
	
	return dist;
}

var state$1 = {};

var hasRequiredState$1;

function requireState$1 () {
	if (hasRequiredState$1) return state$1;
	hasRequiredState$1 = 1;
	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT License.
	Object.defineProperty(state$1, "__esModule", { value: true });
	state$1.state = void 0;
	/**
	 * @internal
	 *
	 * Holds the singleton instrumenter, to be shared across CJS and ESM imports.
	 */
	state$1.state = {
	    instrumenterImplementation: undefined,
	};
	
	return state$1;
}

var state = {};

var hasRequiredState;

function requireState () {
	if (hasRequiredState) return state;
	hasRequiredState = 1;
	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT License.
	Object.defineProperty(state, "__esModule", { value: true });
	state.state = void 0;
	/**
	 * Holds the singleton operationRequestMap, to be shared across CJS and ESM imports.
	 */
	state.state = {
	    operationRequestMap: new WeakMap(),
	};
	
	return state;
}

export { requireDist$1 as a, requireDist as b, requireState$1 as c, requireState as d, requireMinimatch as r };
