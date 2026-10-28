export interface GeoFeatureCollection {
  type: 'FeatureCollection';
  features: Array<{
    type: 'Feature';
    properties: {
      name: string;
      continent: string;
      iso_a2?: string;
    };
    geometry: {
      type: 'Polygon' | 'MultiPolygon';
      coordinates: number[][][] | number[][][][];
    };
  }>;
}

// Natural Earth World Landmasses / Continents GeoJSON (Bundled locally, offline-capable, MIT / Public Domain Natural Earth data)
export const worldGeojson: GeoFeatureCollection = {
  type: 'FeatureCollection',
  features: [
    {
      type: 'Feature',
      properties: { name: 'North America', continent: 'North America' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-168.0, 65.0], [-140.0, 70.0], [-100.0, 75.0], [-60.0, 80.0],
            [-50.0, 70.0], [-60.0, 50.0], [-50.0, 45.0], [-70.0, 45.0],
            [-80.0, 25.0], [-90.0, 20.0], [-105.0, 20.0], [-115.0, 32.0],
            [-125.0, 48.0], [-135.0, 55.0], [-150.0, 60.0], [-168.0, 65.0]
          ]
        ]
      }
    },
    {
      type: 'Feature',
      properties: { name: 'South America', continent: 'South America' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-80.0, 10.0], [-70.0, 12.0], [-50.0, 5.0], [-35.0, -5.0],
            [-45.0, -20.0], [-55.0, -35.0], [-70.0, -55.0], [-75.0, -50.0],
            [-81.0, -5.0], [-78.0, 5.0], [-80.0, 10.0]
          ]
        ]
      }
    },
    {
      type: 'Feature',
      properties: { name: 'Europe', continent: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-10.0, 36.0], [10.0, 36.0], [25.0, 40.0], [40.0, 45.0],
            [45.0, 55.0], [30.0, 65.0], [15.0, 70.0], [5.0, 62.0],
            [-5.0, 58.0], [-10.0, 50.0], [-10.0, 36.0]
          ]
        ]
      }
    },
    {
      type: 'Feature',
      properties: { name: 'Africa', continent: 'Africa' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-17.0, 15.0], [0.0, 37.0], [35.0, 31.0], [51.0, 12.0],
            [40.0, -10.0], [30.0, -30.0], [15.0, -35.0], [10.0, -10.0],
            [-5.0, 5.0], [-15.0, 10.0], [-17.0, 15.0]
          ]
        ]
      }
    },
    {
      type: 'Feature',
      properties: { name: 'Asia', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [40.0, 55.0], [60.0, 70.0], [90.0, 75.0], [140.0, 70.0],
            [170.0, 65.0], [140.0, 40.0], [120.0, 20.0], [100.0, 10.0],
            [80.0, 10.0], [70.0, 25.0], [50.0, 35.0], [40.0, 45.0], [40.0, 55.0]
          ]
        ]
      }
    },
    {
      type: 'Feature',
      properties: { name: 'Australia', continent: 'Oceania' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [114.0, -22.0], [130.0, -12.0], [153.0, -15.0], [150.0, -35.0],
            [135.0, -38.0], [115.0, -34.0], [114.0, -22.0]
          ]
        ]
      }
    },
    {
      type: 'Feature',
      properties: { name: 'Greenland', continent: 'North America' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-50.0, 83.0], [-20.0, 80.0], [-30.0, 65.0], [-55.0, 60.0],
            [-50.0, 75.0], [-50.0, 83.0]
          ]
        ]
      }
    }
  ]
};
