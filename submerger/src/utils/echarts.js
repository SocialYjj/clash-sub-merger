import * as echarts from 'echarts/core';
import {
  LineChart,
  EffectScatterChart,
  LinesChart,
  ScatterChart,
} from 'echarts/charts';
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
  GeoComponent,
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

// Register only the required features to keep the bundle lean
echarts.use([
  LineChart,
  EffectScatterChart,
  LinesChart,
  ScatterChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  GeoComponent,
  CanvasRenderer,
]);

export default echarts;
export { echarts };
