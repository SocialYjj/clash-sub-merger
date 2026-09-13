import { useState } from 'react';
import request from '../../utils/request';
import { parseNodeTestResponse, getNodeInvalidReasonLabel, mergeIpProfiles } from './nodeHelpers.js';

const API_BASE = '/api';

export default function useNodeTesting({ showToast, testTimeout, selectedGeoipApi }) {
  const [testingByNode, setTestingByNode] = useState({});
  const [nodeTestResults, setNodeTestResults] = useState({});
  // Batch testing state (moved from Nodes.jsx together with batchTestNodes)
  const [batchTesting, setBatchTesting] = useState(false);
  const [batchTestProgress, setBatchTestProgress] = useState({ current: 0, total: 0 });

  // Test single node
  const mergeNodeTestResults = (updates) => {
    setNodeTestResults(prev => {
      const next = { ...prev };
      Object.entries(updates || {}).forEach(([nodeKey, result]) => {
        next[nodeKey] = { ...prev[nodeKey], ...result };
      });
      return next;
    });
  };

  const setNodeTesting = (nodeKey, type) => {
    setTestingByNode(prev => ({ ...prev, [nodeKey]: type }));
  };

  const clearNodeTesting = (nodeKey) => {
    setTestingByNode(prev => {
      const next = { ...prev };
      delete next[nodeKey];
      return next;
    });
  };

  const testNode = async (node, isRegionTest = false) => {
    if (node.sourceType === 'chain') {
      showToast?.('链式代理需要通过最终订阅测试，暂不支持单节点测速', 'warning');
      return;
    }
    if (node.valid === false) {
      showToast?.(getNodeInvalidReasonLabel(node.invalid_reason), 'warning');
      return;
    }
    setNodeTesting(node.nodeKey, isRegionTest ? 'region' : 'latency');
    try {
      const payload = {
        test_latency: !isRegionTest,
        test_speed: false,
        test_region: isRegionTest,
        test_ip_profile: false,
        test_radar: false,
        timeout: testTimeout
      };
      if (isRegionTest) {
        payload.geoip_api = selectedGeoipApi;
      }
      const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, payload);
      const testPayload = parseNodeTestResponse(res);
      setNodeTestResults(prev => {
        const newResult = { ...prev[node.nodeKey] };
        if (isRegionTest) {
          newResult.region = testPayload.region;
          newResult.city = testPayload.city;
          newResult.exit_ip = testPayload.exit_ip;
          const mergedIpProfile = mergeIpProfiles(node.ip_profile, testPayload.ip_profile);
          if (mergedIpProfile) {
            newResult.ip_profile = mergedIpProfile;
          }
          newResult.regionError = false;
        } else {
          newResult.latency = testPayload.latency;
          newResult.error = false;
        }
        return { ...prev, [node.nodeKey]: newResult };
      });
    } catch (err) {
      setNodeTestResults(prev => {
        const failedResult = { ...prev[node.nodeKey] };
        const failureMessage = err.response?.data?.detail || err.message || '未知错误';
        if (isRegionTest) {
          failedResult.regionError = true;
          failedResult.regionErrorMessage = failureMessage;
        } else {
          failedResult.latency = null;
          failedResult.error = true;
          failedResult.errorMessage = failureMessage;
        }
        return { ...prev, [node.nodeKey]: failedResult };
      });
      showToast?.(`节点测试失败: ${err.response?.data?.detail || err.message || '未知错误'}`, 'error');
    } finally {
      clearNodeTesting(node.nodeKey);
    }
  };

  // Test single node speed
  const testNodeSpeed = async (node) => {
    if (node.sourceType === 'chain') {
      showToast?.('链式代理需要通过最终订阅测试，暂不支持单节点测速', 'warning');
      return;
    }
    if (node.valid === false) {
      showToast?.(getNodeInvalidReasonLabel(node.invalid_reason), 'warning');
      return;
    }
    setNodeTesting(node.nodeKey, 'speed');
    try {
      const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
        test_latency: false,
        test_speed: true,
        test_region: false,
        timeout: testTimeout
      });
      const testPayload = parseNodeTestResponse(res);
      setNodeTestResults(prev => ({
        ...prev,
        [node.nodeKey]: {
          ...prev[node.nodeKey],
          speed: testPayload.speed,
          peak_speed: testPayload.peak_speed,
          speed_error: false,
          speedErrorMessage: undefined
        }
      }));
    } catch (err) {
      setNodeTestResults(prev => ({
        ...prev,
        [node.nodeKey]: {
          ...prev[node.nodeKey],
          speed: null,
          peak_speed: null,
          speed_error: true,
          speedErrorMessage: err.response?.data?.detail || err.message || '未知错误'
        }
      }));
      showToast?.(`速度测试失败: ${err.response?.data?.detail || err.message || '未知错误'}`, 'error');
    } finally {
      clearNodeTesting(node.nodeKey);
    }
  };

  const testNodeMetadata = async (node, metadataType) => {
    if (node.sourceType === 'chain') {
      showToast?.('链式代理需要通过最终订阅测试，暂不支持单节点信息检测', 'warning');
      return;
    }
    if (node.valid === false) {
      showToast?.(getNodeInvalidReasonLabel(node.invalid_reason), 'warning');
      return;
    }

    const requestFields = {
      test_latency: false,
      test_speed: false,
      test_region: metadataType === 'region',
      test_ip_profile: metadataType === 'ippure',
      test_radar: metadataType === 'radar',
      timeout: testTimeout,
    };
    if (metadataType !== 'ippure') {
      requestFields.geoip_api = selectedGeoipApi;
    }

    setNodeTesting(node.nodeKey, metadataType);
    try {
      const res = await request.post(
        `${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`,
        requestFields,
      );
      const testPayload = parseNodeTestResponse(res);
      setNodeTestResults(prev => {
        const next = { ...prev[node.nodeKey] };
        const mergedIpProfile = mergeIpProfiles(
          next.ip_profile || node.ip_profile,
          testPayload.ip_profile,
        );
        if (mergedIpProfile) next.ip_profile = mergedIpProfile;
        if (testPayload.exit_ip) next.exit_ip = testPayload.exit_ip;
        if (metadataType === 'region') {
          next.region = testPayload.region;
          next.city = testPayload.city;
          next.regionError = false;
        } else if (metadataType === 'ippure') {
          next.ippureError = false;
        } else {
          next.radarError = false;
        }
        return { ...prev, [node.nodeKey]: next };
      });
    } catch (err) {
      const failureMessage = err.response?.data?.detail || err.message || '未知错误';
      setNodeTestResults(prev => ({
        ...prev,
        [node.nodeKey]: {
          ...prev[node.nodeKey],
          ...(metadataType === 'region'
            ? { regionError: true, regionErrorMessage: failureMessage }
            : metadataType === 'ippure'
              ? { ippureError: true, ippureErrorMessage: failureMessage }
              : { radarError: true, radarErrorMessage: failureMessage }),
        },
      }));
      showToast?.(`节点信息检测失败: ${failureMessage}`, 'error');
    } finally {
      clearNodeTesting(node.nodeKey);
    }
  };

  const testNodeIppure = (node) => testNodeMetadata(node, 'ippure');
  const testNodeRadar = (node) => testNodeMetadata(node, 'radar');

  // Batch test nodes - latency first with concurrency, then region.
  // Moved out of Nodes.jsx: it receives the page's current filtered node list
  // plus the page state it reads via `options`, so this hook does not close
  // over the filteredNodes memo (nodeTestResults -> allNodes -> filteredNodes
  // would be a render-order cycle). `testTimeout`, `selectedGeoipApi`,
  // `showToast`, result merging and the batch progress state come from the
  // hook scope; the page passes everything else at call time.
  const batchTestNodes = async (filteredNodesList, options = {}) => {
    const {
      selectedNodes,
      testConcurrency,
      testLatency,
      testRegion,
      testIppure,
      testRadar,
      testSpeed,
      setShowBatchTestMenu,
    } = options;

    // Only test selected nodes, no longer fall back to all nodes
    if (selectedNodes.size === 0) {
      showToast?.('请先在左侧选择要检测的节点', 'warning');
      return;
    }

    const selectedNodesToTest = filteredNodesList.filter(n => selectedNodes.has(n.nodeKey));
    const skippedChainCount = selectedNodesToTest.filter(n => n.sourceType === 'chain').length;
    const skippedIncompatibleCount = selectedNodesToTest.filter(
      n => n.sourceType !== 'chain' && n.valid === false,
    ).length;
    const nodesToTest = selectedNodesToTest.filter(
      n => n.sourceType !== 'chain' && n.valid !== false,
    );

    if (skippedChainCount > 0 || skippedIncompatibleCount > 0) {
      const skipped = [];
      if (skippedChainCount > 0) skipped.push(`${skippedChainCount} 个链式代理`);
      if (skippedIncompatibleCount > 0) skipped.push(`${skippedIncompatibleCount} 个不兼容节点`);
      showToast?.(`已跳过${skipped.join('、')}`, 'info');
    }

    if (nodesToTest.length === 0) {
      showToast?.('没有可测试的节点', 'error');
      return;
    }

    if (!testLatency && !testRegion && !testIppure && !testRadar && !testSpeed) {
      showToast?.('请至少选择一项检测内容', 'error');
      return;
    }

    setShowBatchTestMenu(false);
    setBatchTesting(true);

    const totalSteps = (testLatency ? nodesToTest.length : 0)
      + (testRegion ? nodesToTest.length : 0)
      + (testIppure ? nodesToTest.length : 0)
      + (testRadar ? nodesToTest.length : 0)
      + (testSpeed ? nodesToTest.length : 0);
    let currentStep;
    const firstPhase = testLatency
      ? '延迟'
      : testRegion
        ? 'IP/地区'
        : testIppure
          ? 'IP属性'
          : testRadar
            ? '人机流量比'
            : '速度';
    setBatchTestProgress({ current: 0, total: totalSteps, phase: firstPhase });

    // Batch update results to reduce re-renders
    const batchResults = {};
    const saveData = {};  // 用于批量保存的数据结构
    let failedCount = 0;
    const mergeBatchIpProfile = (node, profile) => {
      const savedProfile = saveData[node.sourceId]?.[node.id]?.ip_profile;
      return mergeIpProfiles(savedProfile || node.ip_profile, profile);
    };

    // Phase 1: Test latency with concurrency
    if (testLatency) {
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: true,
              test_speed: false,
              test_region: false,
              timeout: testTimeout,
              batch_mode: true  // 批量模式，不立即保存
            });
            const testPayload = parseNodeTestResponse(res);

            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].latency = testPayload.latency;

            return { nodeKey: node.nodeKey, data: { latency: testPayload.latency, error: false } };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            saveData[node.sourceId][node.id] = {
              ...(saveData[node.sourceId][node.id] || {}),
              latency: null,
              error: message,
            };
            return { nodeKey: node.nodeKey, data: { latency: null, error: true, errorMessage: message } };
          }
        }));

        // Batch update
        results.forEach(result => {
          if (result.status === 'fulfilled') {
            batchResults[result.value.nodeKey] = { ...batchResults[result.value.nodeKey], ...result.value.data };
          }
        });

        currentStep = Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '延迟' });

        // Update state every batch instead of every node
        mergeNodeTestResults(batchResults);
      }
    }

    // Phase 2: Test region with concurrency
    if (testRegion) {
      const baseStep = testLatency ? nodesToTest.length : 0;
      setBatchTestProgress(prev => ({ ...prev, phase: 'IP/地区' }));
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: false,
              test_speed: false,
              test_region: true,
              timeout: testTimeout,
              geoip_api: selectedGeoipApi,
              batch_mode: true  // 批量模式
            });
            const testPayload = parseNodeTestResponse(res);

            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].exit_ip = testPayload.exit_ip;
            const mergedIpProfile = mergeBatchIpProfile(node, testPayload.ip_profile);
            if (mergedIpProfile) {
              saveData[node.sourceId][node.id].ip_profile = mergedIpProfile;
            }
            saveData[node.sourceId][node.id].region = testPayload.region;
            saveData[node.sourceId][node.id].city = testPayload.city;

            const regionData = {
              region: testPayload.region,
              city: testPayload.city,
              exit_ip: testPayload.exit_ip,
              regionError: false,
            };
            if (mergedIpProfile) {
              regionData.ip_profile = mergedIpProfile;
            }
            return { nodeKey: node.nodeKey, data: regionData };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            saveData[node.sourceId][node.id] = {
              ...(saveData[node.sourceId][node.id] || {}),
              exit_ip: null,
              region: null,
              city: null,
              error: message,
            };
            return { nodeKey: node.nodeKey, data: { regionError: true, regionErrorMessage: message } };
          }
        }));

        // Batch update
        results.forEach(result => {
          if (result.status === 'fulfilled' && result.value) {
            batchResults[result.value.nodeKey] = { ...batchResults[result.value.nodeKey], ...result.value.data };
          }
        });

        currentStep = baseStep + Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: 'IP/地区' });

        // Update state every batch
        mergeNodeTestResults(batchResults);
      }
    }

    // Phase 3: Test IPPure attributes with the same concurrency as region.
    if (testIppure) {
      setBatchTestProgress(prev => ({ ...prev, phase: 'IP属性' }));
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: false,
              test_speed: false,
              test_region: false,
              test_ip_profile: true,
              test_radar: false,
              timeout: testTimeout,
              batch_mode: true,
            });
            const testPayload = parseNodeTestResponse(res);
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].exit_ip = testPayload.exit_ip;
            const mergedIpProfile = mergeBatchIpProfile(node, testPayload.ip_profile);
            if (mergedIpProfile) {
              saveData[node.sourceId][node.id].ip_profile = mergedIpProfile;
            }
            return {
              nodeKey: node.nodeKey,
              data: {
                exit_ip: testPayload.exit_ip,
                ip_profile: mergedIpProfile,
                ippureError: false,
              },
            };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            return {
              nodeKey: node.nodeKey,
              data: { ippureError: true, ippureErrorMessage: message },
            };
          }
        }));

        results.forEach(result => {
          if (result.status === 'fulfilled') {
            batchResults[result.value.nodeKey] = {
              ...batchResults[result.value.nodeKey],
              ...result.value.data,
            };
          }
        });
        currentStep = (testLatency ? nodesToTest.length : 0)
          + (testRegion ? nodesToTest.length : 0)
          + Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: 'IP属性' });
        mergeNodeTestResults(batchResults);
      }
    }

    // Phase 4: Test Cloudflare Radar human/bot ratio.
    if (testRadar) {
      const baseStep = (testLatency ? nodesToTest.length : 0)
        + (testRegion ? nodesToTest.length : 0)
        + (testIppure ? nodesToTest.length : 0);
      setBatchTestProgress(prev => ({ ...prev, phase: '人机流量比' }));
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: false,
              test_speed: false,
              test_region: false,
              test_ip_profile: false,
              test_radar: true,
              timeout: testTimeout,
              geoip_api: selectedGeoipApi,
              batch_mode: true,
            });
            const testPayload = parseNodeTestResponse(res);
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].exit_ip = testPayload.exit_ip;
            const mergedIpProfile = mergeBatchIpProfile(node, testPayload.ip_profile);
            if (mergedIpProfile) {
              saveData[node.sourceId][node.id].ip_profile = mergedIpProfile;
            }
            return {
              nodeKey: node.nodeKey,
              data: {
                exit_ip: testPayload.exit_ip,
                ip_profile: mergedIpProfile,
                radarError: false,
              },
            };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            return {
              nodeKey: node.nodeKey,
              data: { radarError: true, radarErrorMessage: message },
            };
          }
        }));

        results.forEach(result => {
          if (result.status === 'fulfilled') {
            batchResults[result.value.nodeKey] = {
              ...batchResults[result.value.nodeKey],
              ...result.value.data,
            };
          }
        });
        currentStep = baseStep + Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '人机流量比' });
        mergeNodeTestResults(batchResults);
      }
    }

    // Phase 5: Test speed with concurrency (lower concurrency for speed test)
    if (testSpeed) {
      const baseStep = (testLatency ? nodesToTest.length : 0)
        + (testRegion ? nodesToTest.length : 0)
        + (testIppure ? nodesToTest.length : 0)
        + (testRadar ? nodesToTest.length : 0);
      setBatchTestProgress(prev => ({ ...prev, phase: '速度' }));
      // Use lower concurrency for speed test (max 2) to avoid bandwidth saturation
      const speedConcurrency = Math.min(testConcurrency, 2);
      for (let i = 0; i < nodesToTest.length; i += speedConcurrency) {
        const batch = nodesToTest.slice(i, i + speedConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: false,
              test_speed: true,
              test_region: false,
              timeout: testTimeout,
              batch_mode: true  // 批量模式
            });
            const testPayload = parseNodeTestResponse(res);

            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].speed = testPayload.speed;
            saveData[node.sourceId][node.id].peak_speed = testPayload.peak_speed;

            return { nodeKey: node.nodeKey, data: { speed: testPayload.speed, peak_speed: testPayload.peak_speed, speed_error: false } };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            saveData[node.sourceId][node.id] = {
              ...(saveData[node.sourceId][node.id] || {}),
              speed: null,
              error: message,
            };
            return { nodeKey: node.nodeKey, data: { speed: null, peak_speed: null, speed_error: true, speedErrorMessage: message } };
          }
        }));

        // Batch update
        results.forEach(result => {
          if (result.status === 'fulfilled' && result.value) {
            batchResults[result.value.nodeKey] = { ...batchResults[result.value.nodeKey], ...result.value.data };
          }
        });

        currentStep = baseStep + Math.min(i + speedConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '速度' });

        // Update state every batch
        mergeNodeTestResults(batchResults);
      }
    }

    // 批量保存所有测试结果
    try {
      const expectedSaveCount = Object.values(saveData).reduce((total, sourceNodes) => (
        total + Object.values(sourceNodes).filter(result => (
          Object.entries(result).some(([key, value]) => key !== 'error' && value !== null && value !== undefined)
        )).length
      ), 0);
      const saveResponse = await request.post(`${API_BASE}/nodes/batch-save`, { results: saveData });
      const savedCount = Number(saveResponse?.data?.saved_count || 0);
      const unmatchedCount = Array.isArray(saveResponse?.data?.unmatched_node_ids)
        ? saveResponse.data.unmatched_node_ids.length
        : 0;
      if (savedCount < expectedSaveCount || unmatchedCount > 0) {
        showToast?.(`测试完成，但仅保存 ${savedCount}/${expectedSaveCount} 个结果，请刷新后重试`, 'error');
      } else if (failedCount > 0) {
        showToast?.(`测试完成，${failedCount} 个节点失败，其余结果已保存`, 'warning');
      } else {
        showToast?.(`测试完成，共测试 ${nodesToTest.length} 个节点，结果已保存`);
      }
    } catch (error) {
      showToast?.(`测试完成，但保存失败: ${error.message}`, 'error');
    }

    setBatchTesting(false);
  };

  return {
    nodeTestResults,
    setNodeTestResults,
    mergeNodeTestResults,
    testingByNode,
    testNode,
    testNodeSpeed,
    testNodeMetadata,
    testNodeIppure,
    testNodeRadar,
    batchTestNodes,
    batchTesting,
    batchTestProgress,
  };
}
