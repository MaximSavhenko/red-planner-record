import dayjs from 'dayjs'
import { type Formatters } from 'react-day-picker'

const seasonEmoji: Record<string, string> = {
	winter: '⛄️',
	spring: '🌸',
	summer: '🌻',
	autumn: '🍂'
}

const getSeason = (date: Date): keyof typeof seasonEmoji => {
	const m = date.getMonth() + 1
	if (m > 2 && m < 6) return 'spring'
	if (m > 5 && m < 9) return 'summer'
	if (m > 8 && m < 12) return 'autumn'
	return 'winter'
}

export const customFormatters: Partial<Formatters> = {
	formatCaption: (date: Date) => {
		const season = getSeason(date)
		return `${seasonEmoji[season]} ${dayjs(date).format('MMMM')}`
	}
}
