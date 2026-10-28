import * as topojson from 'topojson-client';
import worldAtlasData from 'world-atlas/countries-110m.json';

/**
 * Natural Earth World Boundaries Dataset (1:110m resolution)
 * Source: Natural Earth (Public Domain) via world-atlas (ISC License)
 * Locally bundled and offline-capable.
 */
export const naturalEarthTopology = worldAtlasData;

// Pre-computed GeoJSON landmasses
export const worldLandGeoJSON = topojson.feature(
  worldAtlasData as any,
  (worldAtlasData as any).objects.land
);

// Pre-computed GeoJSON country boundaries
export const worldCountriesGeoJSON = topojson.feature(
  worldAtlasData as any,
  (worldAtlasData as any).objects.countries
);

// Internal country boundary mesh
export const worldBordersMesh = topojson.mesh(
  worldAtlasData as any,
  (worldAtlasData as any).objects.countries,
  (a: any, b: any) => a !== b
);
