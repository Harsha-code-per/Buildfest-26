"use client";

import { useEffect, useRef } from "react";
import * as THREE from "three";

/**
 * Cinematic scroll-driven background: a field of crystalline "threat shards"
 * that rotate as a group, rise, and dolly the camera back on scroll, with lerped
 * pointer parallax. Adapted from the cinematic-3d-landing technique into a Next
 * client component. Grain + vignette live in CSS (globals.css), not here.
 */

// ponytail: the feel lives in these knobs — tune, don't rewrite.
const OBJECT_COUNT = 70; // density of the field
const FIELD_RADIUS = 9; // radial spread
const FOG_DENSITY = 0.05; // depth falloff into the dark base
const DOLLY = 8; // how far the camera pulls back across a full scroll
const CAM_Z = 12; // resting camera distance

// Material tones = the app's own triage palette, so the field reads as threats.
const TONES = [0xef4444, 0xf59e0b, 0x38bdf8, 0x8b5cf6, 0x64748b];
const BASE = 0x05070d;

/** A faceted crystal shard: low-poly icosahedron elongated + pinched to a point. */
function makeShard(): THREE.BufferGeometry {
  const g = new THREE.IcosahedronGeometry(1, 0);
  const pos = g.attributes.position as THREE.BufferAttribute;
  const v = new THREE.Vector3();
  let maxY = 0;
  for (let i = 0; i < pos.count; i++) {
    v.fromBufferAttribute(pos, i);
    // Pull vertices near the vertical axis further along y -> a crystal point.
    const axial = Math.exp(-(v.x * v.x + v.z * v.z) / 0.25);
    v.y *= 1.7 * (1 + axial * 0.9);
    v.x *= 0.72;
    v.z *= 0.72;
    pos.setXYZ(i, v.x, v.y, v.z);
    maxY = Math.max(maxY, Math.abs(v.y));
  }
  g.computeVertexNormals();
  // Self-check: the pinch/elongation actually pulled a point beyond the base radius.
  console.assert(maxY > 1.3, "makeShard: geometry did not elongate as expected");
  return g;
}

export default function Hero3D() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const reduce =
      typeof matchMedia === "function" &&
      matchMedia("(prefers-reduced-motion: reduce)").matches;

    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(window.innerWidth, window.innerHeight);

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(BASE, FOG_DENSITY);

    const camera = new THREE.PerspectiveCamera(
      55,
      window.innerWidth / window.innerHeight,
      0.1,
      100,
    );
    camera.position.set(0, 0, CAM_Z);

    // Cool 4-light rig.
    scene.add(new THREE.AmbientLight(0x2a3550, 0.6));
    const key = new THREE.DirectionalLight(0xbfe3ff, 1.1);
    key.position.set(4, 6, 8);
    scene.add(key);
    const rim = new THREE.DirectionalLight(0x38bdf8, 0.8); // sky rim from behind
    rim.position.set(-6, 2, -8);
    scene.add(rim);
    const fill = new THREE.PointLight(0x8b5cf6, 0.7, 40); // violet fill, flickers
    fill.position.set(0, -3, 6);
    scene.add(fill);

    // One shared geometry; per-mesh material tone. A Group IS the particle system.
    const shard = makeShard();
    const materials = TONES.map(
      (c) =>
        new THREE.MeshStandardMaterial({
          color: c,
          emissive: c,
          emissiveIntensity: 0.22,
          metalness: 0.35,
          roughness: 0.35,
          flatShading: true,
        }),
    );

    const group = new THREE.Group();
    type Drift = { spin: THREE.Vector3; phase: number; y0: number };
    const drifts: Drift[] = [];
    for (let i = 0; i < OBJECT_COUNT; i++) {
      const mesh = new THREE.Mesh(shard, materials[i % materials.length]);
      const a = Math.random() * Math.PI * 2;
      const r = Math.pow(Math.random(), 0.7) * FIELD_RADIUS; // denser core
      const y0 = (Math.random() - 0.5) * 9;
      mesh.position.set(Math.cos(a) * r, y0, Math.sin(a) * r);
      mesh.rotation.set(Math.random() * 6, Math.random() * 6, Math.random() * 6);
      const s = 0.3 + Math.random() * 0.8;
      mesh.scale.setScalar(s);
      group.add(mesh);
      drifts.push({
        spin: new THREE.Vector3(
          (Math.random() - 0.5) * 0.3,
          (Math.random() - 0.5) * 0.3,
          (Math.random() - 0.5) * 0.3,
        ),
        phase: Math.random() * Math.PI * 2,
        y0,
      });
    }
    scene.add(group);

    // Scroll progress 0..1 and lerped pointer parallax.
    let progress = 0;
    const pointer = { x: 0, y: 0 };
    const px = { x: 0, y: 0 };

    const onScroll = () => {
      const max = document.documentElement.scrollHeight - window.innerHeight;
      progress = max > 0 ? window.scrollY / max : 0;
    };
    const onPointer = (e: PointerEvent) => {
      pointer.x = e.clientX / window.innerWidth - 0.5;
      pointer.y = e.clientY / window.innerHeight - 0.5;
    };
    const onResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("pointermove", onPointer, { passive: true });
    window.addEventListener("resize", onResize);

    const clock = new THREE.Clock();
    let raf = 0;
    const target = new THREE.Vector3();

    const frame = () => {
      const t = clock.getElapsedTime();

      // Group choreography: rotate as a whole, rise, camera dollies back.
      group.rotation.y = t * 0.05 + progress * 1.4;
      group.position.y = -progress * 4;
      camera.position.z = CAM_Z + progress * DOLLY;

      // Lerped pointer parallax — never assign raw pointer to the camera.
      px.x += (pointer.x - px.x) * 0.05;
      px.y += (pointer.y - px.y) * 0.05;
      camera.position.x = px.x * 3;
      camera.position.y = -px.y * 2;

      // Per-object drift + float; keep the rising field framed.
      for (let i = 0; i < group.children.length; i++) {
        const m = group.children[i] as THREE.Mesh;
        const d = drifts[i];
        m.rotation.x += d.spin.x * 0.01;
        m.rotation.y += d.spin.y * 0.01;
        m.rotation.z += d.spin.z * 0.01;
        m.position.y = d.y0 + Math.sin(t + d.phase) * 0.3;
      }
      fill.intensity = 0.6 + Math.sin(t * 3) * 0.15; // subtle flicker

      target.set(0, group.position.y * 0.5, 0);
      camera.lookAt(target);

      renderer.render(scene, camera);
      raf = requestAnimationFrame(frame);
    };

    if (reduce) {
      // Static, framed scene — no motion for users who ask for none.
      camera.lookAt(0, 0, 0);
      renderer.render(scene, camera);
    } else {
      frame();
    }

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("pointermove", onPointer);
      window.removeEventListener("resize", onResize);
      shard.dispose();
      materials.forEach((m) => m.dispose());
      renderer.dispose();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 -z-10 h-full w-full"
    />
  );
}
