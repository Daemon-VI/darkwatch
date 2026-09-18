/*
 * Hero background: contour lines of an animated noise field, with a hill under the pointer.
 * A port of the owner's portfolio shader to plain JS, so the two sites read as one hand.
 *
 * Raw WebGL2: one full-screen triangle does not need a scene graph. Colours come from the CSS
 * tokens, the pixel budget is capped for integrated graphics, and it degrades to the section's
 * CSS gradient when WebGL2 is missing or the visitor asked for reduced motion.
 */
(function () {
  'use strict';

  const VS = `#version 300 es
in vec2 a;
void main() { gl_Position = vec4(a, 0.0, 1.0); }`;

  const FS = `#version 300 es
precision highp float;
uniform vec2 uRes;
uniform float uTime;
uniform vec2 uMouse;
uniform float uHover;
uniform vec3 uCool;
uniform vec3 uHot;
uniform float uReveal;
uniform float uFade;
out vec4 outColor;

float hash(vec2 p) {
  p = fract(p * vec2(123.34, 456.21));
  p += dot(p, p + 45.32);
  return fract(p.x * p.y);
}
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), u.x),
             mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x), u.y);
}
const mat2 ROT = mat2(0.8, -0.6, 0.6, 0.8);
float fbm3(vec2 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 3; i++) { v += a * noise(p); p = ROT * p * 2.02; a *= 0.5; }
  return v;
}
float fbm4(vec2 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 4; i++) { v += a * noise(p); p = ROT * p * 2.02; a *= 0.5; }
  return v;
}
void main() {
  float aspect = uRes.x / uRes.y;
  vec2 uv = gl_FragCoord.xy / uRes;
  vec2 p = vec2(uv.x * aspect, uv.y);
  vec2 m = vec2(uMouse.x * aspect, uMouse.y);
  float t = uTime * 0.03;

  vec2 q = vec2(fbm3(p * 1.25 + t), fbm3(p * 1.25 - t + 3.1));
  float h = fbm4(p * 1.05 + q * 0.95 + vec2(t * 0.6, 0.0));

  float d = length(p - m);
  h += exp(-d * d * 9.0) * 0.26 * uHover;

  float bands = h * 22.0;
  float fw = fwidth(bands);
  float g = abs(fract(bands - 0.5) - 0.5);
  float major = 1.0 - step(0.5, mod(floor(bands + 0.5), 5.0));
  float line = 1.0 - smoothstep(0.0, fw * (1.1 + major * 0.7), g);

  vec3 ground = vec3(0.059, 0.067, 0.102);
  float near = exp(-d * d * 14.0) * uHover;
  vec3 lineColor = mix(uCool, uHot, clamp(near * 1.7, 0.0, 1.0));

  float strength = line * mix(0.24, 0.72, major) * (1.0 + near * 0.6);
  float fadeY = smoothstep(0.0, 0.42, uv.y);
  float fadeX = 0.5 + 0.5 * smoothstep(0.0, 0.6, uv.x);
  float r = length((uv - 0.5) * vec2(aspect, 1.0));
  float reveal = 1.0 - smoothstep(uReveal * 1.35 - 0.18, uReveal * 1.35, r);
  float k = clamp(strength * fadeY * fadeX * reveal * uFade, 0.0, 1.0);
  outColor = vec4(mix(ground, lineColor, k), 1.0);
}`;

  const MAX_PIXELS = 1.1e6; // integrated graphics: keep the fragment count modest
  const NOOP = { setFade() {}, destroy() {} };

  function cssColour(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const m = /^#([0-9a-f]{6})$/i.exec(v);
    if (!m) return fallback;
    const n = parseInt(m[1], 16);
    return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
  }

  window.initField = function initField(canvas, opts) {
    const options = opts || {};
    if (!canvas) return NOOP;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return NOOP;
    const gl = canvas.getContext('webgl2', { antialias: false, alpha: false, powerPreference: 'low-power' });
    if (!gl) return NOOP;

    const compile = (type, src) => {
      const s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        console.warn('[field]', gl.getShaderInfoLog(s));
        return null;
      }
      return s;
    };
    const vs = compile(gl.VERTEX_SHADER, VS);
    const fs = compile(gl.FRAGMENT_SHADER, FS);
    if (!vs || !fs) return NOOP;
    const prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      console.warn('[field]', gl.getProgramInfoLog(prog));
      return NOOP;
    }
    gl.useProgram(prog);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'a');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

    const u = (n) => gl.getUniformLocation(prog, n);
    const uRes = u('uRes'), uTime = u('uTime'), uMouse = u('uMouse'), uHover = u('uHover');
    const uCool = u('uCool'), uHot = u('uHot'), uReveal = u('uReveal'), uFade = u('uFade');
    gl.uniform3fv(uCool, cssColour('--contour', [0.357, 0.42, 0.839]));
    gl.uniform3fv(uHot, cssColour('--accent', [0.957, 0.71, 0.271]));

    let width = 0, height = 0;
    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      let w = Math.round(rect.width * dpr), h = Math.round(rect.height * dpr);
      const over = (w * h) / MAX_PIXELS;
      if (over > 1) {
        const k = Math.sqrt(over);
        w = Math.round(w / k);
        h = Math.round(h / k);
      }
      if (w === width && h === height) return;
      width = w; height = h;
      canvas.width = w; canvas.height = h;
      gl.viewport(0, 0, w, h);
      gl.uniform2f(uRes, w, h);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    const mouse = { x: 0.5, y: 0.6, tx: 0.5, ty: 0.6, hover: 0, thover: 0 };
    const onMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      mouse.tx = (e.clientX - rect.left) / rect.width;
      mouse.ty = 1 - (e.clientY - rect.top) / rect.height;
      mouse.thover = e.clientY - rect.top > 0 && e.clientY < rect.bottom ? 1 : 0;
    };
    const onLeave = () => { mouse.thover = 0; };
    window.addEventListener('pointermove', onMove, { passive: true });
    window.addEventListener('pointerleave', onLeave, { passive: true });

    let raf = 0, t0 = performance.now(), reveal = 0, fade = 1, paused = false;
    const frame = (now) => {
      raf = requestAnimationFrame(frame);
      if (paused) return;
      const t = (now - t0) / 1000;
      reveal = Math.min(1, reveal + (1 - reveal) * 0.022 + 0.004);
      mouse.x += (mouse.tx - mouse.x) * 0.08;
      mouse.y += (mouse.ty - mouse.y) * 0.08;
      mouse.hover += (mouse.thover - mouse.hover) * 0.06;
      gl.uniform1f(uTime, t);
      gl.uniform2f(uMouse, mouse.x, mouse.y);
      gl.uniform1f(uHover, mouse.hover);
      gl.uniform1f(uReveal, reveal);
      gl.uniform1f(uFade, fade);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    };
    raf = requestAnimationFrame(frame);

    // Stop drawing when the hero is off screen or the tab is hidden: this is a laptop.
    if (options.observe !== false && 'IntersectionObserver' in window) {
      new IntersectionObserver((entries) => { paused = !entries[0].isIntersecting; }, { threshold: 0.01 })
        .observe(canvas);
    }
    document.addEventListener('visibilitychange', () => { paused = document.hidden; });

    return {
      setFade(v) { fade = Math.max(0, Math.min(1, v)); },
      setPaused(v) { paused = !!v; },
      destroy() {
        cancelAnimationFrame(raf);
        ro.disconnect();
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerleave', onLeave);
      },
    };
  };
})();
