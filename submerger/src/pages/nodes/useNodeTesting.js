import { useState } from 'react';
import request from '../../utils/request';
import { parseNodeTestResponse, getNodeInvalidReasonLabel, mergeIpProfiles } from './nodeHelpers.js';

const API_BASE = '/api';

export default function useNodeTesting({ showToast, testTimeout, selectedGeoipApi }) {
  const [testingByNode, setTestingByNode] = useState({});
  const [nodeTestResults, setNodeTestResults] = useState({});

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
  };
}
