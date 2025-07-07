import { DndContext, closestCenter } from '@dnd-kit/core'
import { SortableContext, verticalListSortingStrategy } from '@dnd-kit/sortable'
import { Divide } from 'lucide-react'

import Loader from '@/components/ui/Loader'

import { TimeBlock } from './TimeBlock'
import styles from './TimeBlock.module.scss'
import { calcHoursLef } from './calc-hours-left'
import { useTimeBlockDnd } from './hooks/useTimeBlockDnd'
import { useTimeBlocks } from './hooks/useTimeBlocks'

export function TimeBLockingList() {
	const { items, setItems, isLoading } = useTimeBlocks()
	const { handleDragEnd, sensors } = useTimeBlockDnd(items, setItems)

	if (isLoading) return <Loader />
	const {hoursLeft} = calcHoursLef(items)
	return (
		<div>
			<DndContext
				sensors={sensors}
				collisionDetection={closestCenter}
				onDragEnd={handleDragEnd}
			>
				<div className={styles.list}>
					<SortableContext
						items={items || []}
						strategy={verticalListSortingStrategy}
					>
						{items?.length ? (
							items.map(item => (
								<TimeBlock
									key={item.id}
									item={item}
								/>
							))
						) : (
							<div>Add the first time-block on right panel</div>
						)}
					</SortableContext>
				</div>
			</DndContext>
      <div>
        {hoursLeft > 0 ? 
          `${hoursLeft} hours out of 24 left for sleep` : 'no hours left for sleep'
        }
      </div>
		</div>
	)
}
