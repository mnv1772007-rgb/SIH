import React, { useMemo, useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Line, Stars, Html } from '@react-three/drei'
import * as THREE from 'three'

const RADIUS = 2

/** Convert lat/lon (degrees) to a 3D position on the sphere. */
function latLonToVec3(lat, lon, radius = RADIUS) {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  )
}

/** Dotted point-cloud "continents" shell to give the globe texture. */
function GlobePoints() {
  const positions = useMemo(() => {
    const pts = []
    const count = 1400
    for (let i = 0; i < count; i++) {
      // Fibonacci sphere distribution
      const y = 1 - (i / (count - 1)) * 2
      const r = Math.sqrt(Math.max(0, 1 - y * y))
      const theta = i * 2.399963229728653
      pts.push(Math.cos(theta) * r * RADIUS, y * RADIUS, Math.sin(theta) * r * RADIUS)
    }
    return new Float32Array(pts)
  }, [])

  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={positions.length / 3} array={positions} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial size={0.02} color="#22d3ee" transparent opacity={0.55} sizeAttenuation />
    </points>
  )
}

/** Pulsing marker at the origin IP geolocation. */
function OriginMarker({ position }) {
  const ringRef = useRef()
  const dotRef = useRef()

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime()
    const s = 1 + 0.35 * Math.sin(t * 4)
    if (ringRef.current) {
      ringRef.current.scale.setScalar(s)
      ringRef.current.material.opacity = 0.9 - ((t * 0.8) % 1) * 0.6
      ringRef.current.lookAt(0, 0, 0)
    }
    if (dotRef.current) dotRef.current.lookAt(0, 0, 0)
  })

  return (
    <group position={position}>
      <mesh ref={dotRef}>
        <sphereGeometry args={[0.045, 16, 16]} />
        <meshBasicMaterial color="#f43f5e" />
      </mesh>
      <mesh ref={ringRef}>
        <ringGeometry args={[0.08, 0.1, 32]} />
        <meshBasicMaterial color="#f43f5e" transparent opacity={0.8} side={THREE.DoubleSide} />
      </mesh>
    </group>
  )
}

/** Animated arc tracing the email route from origin to the SOC endpoint. */
function EmailPath({ start, end }) {
  const dotRef = useRef()

  const points = useMemo(() => {
    const mid = start.clone().add(end).multiplyScalar(0.5).normalize().multiplyScalar(RADIUS * 1.45)
    const curve = new THREE.QuadraticBezierCurve3(start, mid, end)
    return curve.getPoints(64)
  }, [start, end])

  useFrame(({ clock }) => {
    if (!dotRef.current) return
    const t = (clock.getElapsedTime() * 0.25) % 1
    const idx = Math.floor(t * (points.length - 1))
    dotRef.current.position.copy(points[idx])
  })

  return (
    <group>
      <Line points={points} color="#f43f5e" lineWidth={1.5} transparent opacity={0.7} dashed dashScale={4} />
      <mesh ref={dotRef}>
        <sphereGeometry args={[0.035, 12, 12]} />
        <meshBasicMaterial color="#fbbf24" />
      </mesh>
      {/* destination marker */}
      <mesh position={end}>
        <sphereGeometry args={[0.035, 12, 12]} />
        <meshBasicMaterial color="#22d3ee" />
      </mesh>
    </group>
  )
}

/** The whole rotating globe assembly. */
function GlobeScene({ lat, lon, country, originIp }) {
  const groupRef = useRef()

  useFrame((_, delta) => {
    if (groupRef.current) groupRef.current.rotation.y += delta * 0.12
  })

  const origin = useMemo(() => latLonToVec3(lat, lon, RADIUS + 0.01), [lat, lon])
  // Destination: analyst SOC (East Coast US)
  const destination = useMemo(() => latLonToVec3(38.9, -77.0, RADIUS + 0.01), [])

  return (
    <>
      <ambientLight intensity={0.6} />
      <pointLight position={[8, 6, 8]} intensity={1.2} color="#22d3ee" />
      <Stars radius={50} depth={40} count={2500} factor={3} saturation={0} fade speed={0.6} />

      <group ref={groupRef}>
        {/* core sphere */}
        <mesh>
          <sphereGeometry args={[RADIUS - 0.02, 48, 48]} />
          <meshStandardMaterial
            color="#0a0f1e"
            emissive="#0e7490"
            emissiveIntensity={0.08}
            transparent
            opacity={0.92}
          />
        </mesh>
        {/* wireframe overlay */}
        <mesh>
          <sphereGeometry args={[RADIUS, 24, 24]} />
          <meshBasicMaterial color="#164e63" wireframe transparent opacity={0.35} />
        </mesh>

        <GlobePoints />
        <OriginMarker position={origin} />
        <EmailPath start={origin} end={destination} />

        <Html position={origin} distanceFactor={10} style={{ pointerEvents: 'none' }}>
          <div className="whitespace-nowrap rounded border border-rose-500/40 bg-black/70 px-2 py-1 font-mono text-[9px] text-rose-300 backdrop-blur-sm">
            ORIGIN · {country} · {originIp}
          </div>
        </Html>
      </group>

      <OrbitControls enableZoom={false} enablePan={false} rotateSpeed={0.5} />
    </>
  )
}

/**
 * 3D Interactive Globe — plots origin_ip / ip_geolocation and traces the email path.
 * Wrap in an ErrorBoundary-safe container; Canvas handles WebGL context itself.
 */
export default function Globe3D({ data }) {
  const { ip_geolocation, origin_ip } = data
  const lat = ip_geolocation?.lat ?? 55.75
  const lon = ip_geolocation?.lon ?? 37.61
  const country = ip_geolocation?.country ?? '??'

  return (
    <div className="relative h-full w-full">
      <Canvas camera={{ position: [0, 1.2, 5.2], fov: 45 }} dpr={[1, 2]}>
        <GlobeScene lat={lat} lon={lon} country={country} originIp={origin_ip} />
      </Canvas>

      {/* HUD overlay */}
      <div className="pointer-events-none absolute left-3 top-3 font-mono text-[10px] leading-relaxed text-cyan-300/80">
        <div>GLOBAL THREAT MAP</div>
        <div className="text-slate-500">ROUTE: {country} → SOC-US-EAST</div>
      </div>
      <div className="pointer-events-none absolute bottom-3 left-3 font-mono text-[10px] text-slate-500">
        LAT {lat.toFixed(2)}° / LON {lon.toFixed(2)}°
      </div>
    </div>
  )
}
