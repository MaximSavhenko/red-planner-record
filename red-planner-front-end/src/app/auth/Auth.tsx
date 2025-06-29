'use client'

import { useMutation } from '@tanstack/react-query'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { SubmitHandler, useForm } from 'react-hook-form'
import { toast } from 'sonner'

import { Heading } from '@/components/ui/Heading'
import { Button } from '@/components/ui/buttons/Button'
import { Field } from '@/components/ui/fields/Field'

import { IAuthForm } from '@/types/auth.types'

import { DASHBOARD_PAGES } from '@/config/page-url.config'

import { authService } from '@/services/auth.service'

export function Auth() {
	const { register, handleSubmit, reset } = useForm<IAuthForm>({
		mode: 'onChange'
	})

	const [isLoginForm, setLoginForm] = useState(false)

	const { push } = useRouter()

	const { mutate } = useMutation({
		mutationKey: ['auth'],
		mutationFn: (data: IAuthForm) =>
			authService.main(isLoginForm ? 'login' : 'register', data),
		onSuccess() {
			toast.success('Successfully logged in !')
			reset()
			push(DASHBOARD_PAGES.HOME)
		}
	})

	const onSubmit: SubmitHandler<IAuthForm> = data => {
		mutate(data)
	}
	return (
		<div className='flex min-h-screen'>
			<form
				onSubmit={handleSubmit(onSubmit)}
				className='w-1/4 m-auto shadow bg-sidebar rounded-xl p-layout'
			>
				<Heading title='Auth' />
				<Field
					id='email'
					label='Email:'
					placeholder='Enter email:'
					type='email'
					extra='mb-4'
					{...register('email', { required: 'Email is required!' })}
				/>

				<Field
					id='password'
					label='Password:'
					placeholder='Enter password:'
					type='password'
					extra='mb-6'
					{...register('password', {
						required: 'Password is required!'
					})}
				/>
				<div className='flex items-center gap-5 justify-center'>
					<Button onClick={() => setLoginForm(true)}>Login</Button>
					<Button onClick={() => setLoginForm(false)}>Register</Button>
				</div>
			</form>
		</div>
	)
}
