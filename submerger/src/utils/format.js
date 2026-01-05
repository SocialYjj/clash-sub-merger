
export const formatTraffic = (bytes) => {
    if (!bytes && bytes !== 0) return null;
    const gb = bytes / (1024 * 1024 * 1024);
    if (gb >= 1024) {
        return `${(gb / 1024).toFixed(2)} TB`;
    }
    if (gb >= 1) {
        return `${gb.toFixed(2)} GB`;
    }
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(2)} MB`;
};

export const formatDate = (timestamp) => {
    if (!timestamp) return null;
    const date = new Date(timestamp * 1000);
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
};

export const getTrafficInfo = (sub) => {
    const upload = sub.upload || 0;
    const download = sub.download || 0;
    const total = sub.total || 0;
    const expire = sub.expire || 0;

    if (!total && !expire) return null;

    const used = upload + download;
    const percent = total ? Math.min((used / total) * 100, 100) : 0;

    return {
        upload: formatTraffic(upload),
        download: formatTraffic(download),
        used: formatTraffic(used),
        total: formatTraffic(total),
        percent: percent.toFixed(1),
        expire: expire ? formatDate(expire) : null,
    };
};

export const getAvatarTheme = (name) => {
    const colors = [
        { bg: 'bg-purple-500/20', text: 'text-purple-400', border: 'border-purple-500/30' },
        { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30' },
        { bg: 'bg-cyan-500/20', text: 'text-cyan-400', border: 'border-cyan-500/30' },
        { bg: 'bg-emerald-500/20', text: 'text-emerald-400', border: 'border-emerald-500/30' },
        { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' },
        { bg: 'bg-pink-500/20', text: 'text-pink-400', border: 'border-pink-500/30' },
    ];
    const colorIndex = name.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) % colors.length;
    return colors[colorIndex];
};
