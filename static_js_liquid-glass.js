/* ============================================================
   Liquid Glass — WebGL background + real refraction for panels
   Settings: Radius 35 | Thickness 81 | Bezel 60 | IOR 2.45
             Blur 0.0  | Specular 0.00 | Tint 2%  | Shadow 0.50
   ============================================================ */
(function () {
    const MAX_RECTS = 48;

    /* All interactive/glass elements on the page */
    const SELECTORS = [
        '.lang-switch',
        '.switcher',
        '.section',
        '.build-btn',
        '.status-bar',
        '.sys-alert',
        '#ble-info', '#bms-info', '#bms-warning', '#gt3-warning',
        '#component-comingsoon', '#mcu-settings .sys-alert',
        '.disclaimer-box',
        '.bms-modal-box'
    ];

    const canvas = document.getElementById('lg-canvas');
    if (!canvas) return;
    const gl = canvas.getContext('webgl', { antialias: true, alpha: false });
    if (!gl) return;

    /* ---- Vertex shader — fullscreen triangle ---- */
    const VERT = `
attribute vec2 aPos;
void main(){ gl_Position = vec4(aPos, 0.0, 1.0); }`;

    /* ---- Fragment shader ---- */
    const FRAG = `
precision highp float;
uniform vec2  uRes;
uniform float uTime;
uniform int   uCount;
#define MAX ${MAX_RECTS}
uniform vec4  uRects[MAX];
uniform float uRadii[MAX];

/* ---- user settings (baked in) ---- */
#define THICKNESS   81.0
#define BEZEL_MAX   60.0
#define IOR         2.45
#define TINT        0.02      /* 2 % white tint  */
#define SHADOW      0.50
#define SPECULAR    0.00      /* specular off     */

/* Signed distance — rounded rectangle */
float sdRR(vec2 p, vec2 b, float r){
    vec2 q = abs(p) - b + r;
    return min(max(q.x,q.y),0.0) + length(max(q,0.0)) - r;
}

/* Glass surface profile */
float surfH(float t){
    float s = 1.0 - t;
    return pow(1.0 - s*s*s*s, 0.25);
}

/* Soft colour blob for the animated background */
vec3 blob(vec2 p, vec2 c, float rad, vec3 col){
    float d = length(p - c) / rad;
    return col * exp(-d*d*1.7);
}

/* Animated dark background — nearly pure black, tiny purple whisper */
vec3 bgCol(vec2 p){
    float t   = uTime;
    /* Base: very dark, essentially black with a faint purple undertone */
    vec3 col  = vec3(0.020, 0.014, 0.032);

    /* Four slow-moving blobs — extremely desaturated, almost invisible */
    col += blob(p,
        uRes * vec2(0.18 + 0.06*sin(t*0.09), 0.74 + 0.05*cos(t*0.12)),
        uRes.y * 0.55, vec3(0.030, 0.022, 0.055));

    col += blob(p,
        uRes * vec2(0.84 + 0.04*sin(t*0.07 + 2.1), 0.32 + 0.08*sin(t*0.10 + 1.0)),
        uRes.y * 0.50, vec3(0.038, 0.028, 0.068));

    col += blob(p,
        uRes * vec2(0.42 + 0.10*cos(t*0.06 + 4.0), 0.16 + 0.05*sin(t*0.08 + 3.0)),
        uRes.y * 0.44, vec3(0.028, 0.022, 0.052));

    col += blob(p,
        uRes * vec2(0.64 + 0.08*sin(t*0.11 + 1.2), 0.90 + 0.04*cos(t*0.09 + 0.5)),
        uRes.y * 0.40, vec3(0.045, 0.036, 0.070));

    /* Gentle breathing pulse */
    col *= 0.97 + 0.03 * sin(t * 0.20);
    return col;
}

void main(){
    vec2 p    = gl_FragCoord.xy;

    /* Find nearest glass panel */
    float best  = 1e9;
    float bRad  = 12.0;
    vec2  bHalf = vec2(20.0);
    for (int i = 0; i < MAX; i++){
        if (i >= uCount) break;
        vec4  R = uRects[i];
        float d = sdRR(p - R.xy, R.zw, uRadii[i]);
        if (d < best){ best = d; bRad = uRadii[i]; bHalf = R.zw; }
    }

    /* ---- Outside glass: background + soft drop shadow ---- */
    if (best > 0.0){
        vec3  base = bgCol(p);
        float s    = exp(-best*best / 800.0) * (SHADOW * 0.60);
        gl_FragColor = vec4(base * (1.0 - s), 1.0);
        return;
    }

    /* ---- Inside glass ---- */
    float distE = -best;
    float bezel = max(min(BEZEL_MAX, min(bRad, min(bHalf.x, bHalf.y)) - 1.0), 1.0);
    float t     = clamp(distE / bezel, 0.0, 1.0);

    float h  = surfH(t);
    float dt = 0.001;
    float dh = (surfH(min(t + dt, 1.0)) - h) / dt;

    /* Physics-based refraction */
    float slopeAngle = atan(dh * (THICKNESS / bezel));
    float sinR       = clamp(sin(slopeAngle) / IOR, -1.0, 1.0);
    float thetaR     = asin(sinR);
    float disp       = h * THICKNESS * (tan(slopeAngle) - tan(thetaR));

    /* Numeric normal gradient over all panels */
    float eps = 0.6;
    float dx  = 0.0, dy = 0.0;
    vec2  e1  = vec2(eps, 0.0);
    vec2  e2  = vec2(0.0, eps);
    for (int i = 0; i < MAX; i++){
        if (i >= uCount) break;
        vec4  R = uRects[i]; float r = uRadii[i];
        dx += sdRR(p + e1 - R.xy, R.zw, r) - sdRR(p - R.xy, R.zw, r);
        dy += sdRR(p + e2 - R.xy, R.zw, r) - sdRR(p - R.xy, R.zw, r);
    }
    vec2 grad = normalize(vec2(dx, dy) + 1e-6);

    /* Refracted background sample (no blur — Blur 0.0) */
    vec2  offset = -grad * disp / uRes;
    vec3  color  = bgCol(p + offset * uRes);

    /* Specular rim — disabled (SPECULAR 0.00) */
    #if SPECULAR > 0.0
    vec2  lightDir  = normalize(vec2(0.45, -0.75));
    float rimDot    = abs(dot(grad, lightDir));
    float rimFall   = 1.0 - smoothstep(0.0, bezel * 0.4, distE);
    color += vec3(pow(rimDot * rimFall, 1.5) * SPECULAR);
    #endif

    /* Subtle inner shadow at bezel edge */
    float innerShadow = 1.0 - smoothstep(0.0, bezel * 0.6, distE);
    color *= mix(1.0, 0.72, innerShadow * 0.28);

    /* 2 % white tint */
    color = mix(color, vec3(1.0), TINT);

    /* Anti-aliased edge */
    float alpha = smoothstep(0.0, 1.5, distE);
    gl_FragColor = vec4(color, alpha);
}`;

    /* ---- Compile helpers ---- */
    function compile(type, src) {
        const sh = gl.createShader(type);
        gl.shaderSource(sh, src);
        gl.compileShader(sh);
        if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)){
            console.error('liquid-glass shader error:', gl.getShaderInfoLog(sh));
            return null;
        }
        return sh;
    }

    const vs = compile(gl.VERTEX_SHADER,   VERT);
    const fs = compile(gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return;
    const prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)){
        console.error('liquid-glass link error:', gl.getProgramInfoLog(prog));
        return;
    }
    gl.useProgram(prog);

    /* Fullscreen triangle */
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 3,-1, -1,3]), gl.STATIC_DRAW);
    const locPos = gl.getAttribLocation(prog, 'aPos');
    gl.enableVertexAttribArray(locPos);
    gl.vertexAttribPointer(locPos, 2, gl.FLOAT, false, 0, 0);

    const U = {
        res:   gl.getUniformLocation(prog, 'uRes'),
        time:  gl.getUniformLocation(prog, 'uTime'),
        count: gl.getUniformLocation(prog, 'uCount'),
        rects: gl.getUniformLocation(prog, 'uRects[0]'),
        radii: gl.getUniformLocation(prog, 'uRadii[0]')
    };

    /* ---- DOM element registry ---- */
    let els = [];
    function refreshElements(){
        els = [];
        SELECTORS.forEach(sel =>
            document.querySelectorAll(sel).forEach(el => els.push(el))
        );
    }
    refreshElements();

    const rectData  = new Float32Array(MAX_RECTS * 4);
    const radiiData = new Float32Array(MAX_RECTS);

    let W = 0, H = 0, dpr = 1;
    function resize(){
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        W   = Math.floor(window.innerWidth  * dpr);
        H   = Math.floor(window.innerHeight * dpr);
        canvas.width  = W;
        canvas.height = H;
        canvas.style.width  = window.innerWidth  + 'px';
        canvas.style.height = window.innerHeight + 'px';
        gl.viewport(0, 0, W, H);
    }
    resize();
    window.addEventListener('resize', () => { resize(); refreshElements(); });

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    /* ---- Render loop ---- */
    const start = performance.now();
    function frame(now){
        const time = (now - start) / 1000;

        let n = 0;
        for (let i = 0; i < els.length && n < MAX_RECTS; i++){
            const el = els[i];
            const r  = el.getBoundingClientRect();
            if (r.width < 2 || r.height < 2) continue;
            if (parseFloat(getComputedStyle(el).opacity) < 0.05) continue;

            const halfW = r.width  / 2;
            const halfH = r.height / 2;
            /* Radius 35 — fixed */
            let rad = Math.min(35, halfW - 1, halfH - 1);
            if (rad < 1) continue;

            rectData[n*4+0] = (r.left + halfW) * dpr;
            rectData[n*4+1] = H - (r.top + halfH) * dpr;
            rectData[n*4+2] = halfW * dpr;
            rectData[n*4+3] = halfH * dpr;
            radiiData[n]    = rad * dpr;
            n++;
        }

        gl.uniform2f(U.res,   W, H);
        gl.uniform1f(U.time,  time);
        gl.uniform1i(U.count, n);
        gl.uniform4fv(U.rects, rectData);
        gl.uniform1fv(U.radii, radiiData);

        gl.clearColor(0.020, 0.012, 0.030, 1);
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.drawArrays(gl.TRIANGLES, 0, 3);

        requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
})();
